#!/usr/bin/env python
import sys
import os
import argparse

####
#
# Enter other desired optional system modules here.
#
####

import netaddr

####
#
# End other desired system modules.
#
####

# Import CloudGenix Python SDK
try:
    import cloudgenix
    jdout = cloudgenix.jdout
    jd = cloudgenix.jd
except ImportError as e:
    cloudgenix = None
    sys.stderr.write("ERROR: 'cloudgenix' python module required. (try 'pip install cloudgenix').\n {0}\n".format(e))
    sys.exit(1)

# Check for cloudgenix_settings.py config file in cwd.
sys.path.append(os.getcwd())
try:
    from cloudgenix_settings import CLOUDGENIX_AUTH_TOKEN

except ImportError:
    # if cloudgenix_settings.py file does not exist,
    # Get AUTH_TOKEN/X_AUTH_TOKEN from env variable, if it exists. X_AUTH_TOKEN takes priority.
    if "X_AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('X_AUTH_TOKEN')
    elif "AUTH_TOKEN" in os.environ:
        CLOUDGENIX_AUTH_TOKEN = os.environ.get('AUTH_TOKEN')
    else:
        # not set
        CLOUDGENIX_AUTH_TOKEN = None

try:
    # Also, seperately try and import USERNAME/PASSWORD from the config file.
    from cloudgenix_settings import CLOUDGENIX_USER, CLOUDGENIX_PASSWORD

except ImportError:
    # will get caught below
    CLOUDGENIX_USER = None
    CLOUDGENIX_PASSWORD = None


# Handle differences between python 2 and 3. Code can use text_type and binary_type instead of str/bytes/unicode etc.
if sys.version_info < (3,):
    text_type = unicode
    binary_type = str
else:
    text_type = str
    binary_type = bytes


####
#
# Start custom modifiable code
#
####
ALREADY_NAGGED_DUP_KEYS = []
GLOBAL_MY_SCRIPT_NAME = "Tag to IP List"
GLOBAL_MY_SCRIPT_VERSION = "v1.0"


class CloudGenixError(Exception):
    """
    Custom exception for errors when not exiting.
    """
    pass


def throw_error(message, resp=None, cr=True):
    """
    Non-recoverable error, print message and raise exception (taken from cloudgenix_config)
    :param message: Message text
    :param resp: Optional - CloudGenix SDK Response object
    :param cr: Optional - Use (or not) Carriage Returns.
    :return: No Return, throws exception.
    """
    output = str(message)
    output2 = str("")
    if cr:
        output += "\n"
    print(output)
    if resp is not None:
        output2 = str(cloudgenix.jdout_detailed(resp))
        if cr:
            output2 += "\n"
        print(output2)

    if output2:
        print(message + output2)

    sys.exit(1)


def throw_warning(message, resp=None, cr=True):
    """
    Recoverable Warning. (taken from cloudgenix_config)
    :param message: Message text
    :param resp: Optional - CloudGenix SDK Response object
    :param cr: Optional - Use (or not) Carriage Returns.
    :return: None
    """
    output = str(message)
    if cr:
        output += "\n"
    print(output)
    if resp is not None:
        output2 = str(cloudgenix.jdout_detailed(resp))
        if cr:
            output2 += "\n"
        print(output2)
    return


def build_lookup_dict(list_content, key_val='name', value_val='id', force_nag=False):
    """
    Build key/value lookup dict (taken from cloudgenix_config)
    :param list_content: List of dicts to derive lookup structs from
    :param key_val: value to extract from entry to be key
    :param value_val: value to extract from entry to be value
    :param force_nag: Bool, if True will nag even if key in already_nagged_dup_keys
    :return: lookup dict
    """

    global ALREADY_NAGGED_DUP_KEYS
    lookup_dict = {}
    blacklist_duplicate_keys = []
    blacklist_duplicate_entries = []

    for item in list_content:
        item_key = item.get(key_val)
        item_value = item.get(value_val)
        # print(item_key, item_value)
        if item_key and item_value is not None:
            # check if it's a duplicate key.
            if str(item_key) in lookup_dict:
                # First duplicate we've seen - save for warning.
                duplicate_value = lookup_dict.get(item_key)
                blacklist_duplicate_keys.append(item_key)
                blacklist_duplicate_entries.append({item_key: duplicate_value})
                blacklist_duplicate_entries.append({item_key: item_value})
                # remove from lookup dict to prevent accidental overlap usage
                del lookup_dict[str(item_key)]

            # check if it was a third+ duplicate key for a previous key
            elif item_key in blacklist_duplicate_keys:
                # save for warning.
                blacklist_duplicate_entries.append({item_key: item_value})

            else:
                # no duplicates, append
                lookup_dict[str(item_key)] = item_value

    for duplicate_key in blacklist_duplicate_keys:
        matching_entries = [entry for entry in blacklist_duplicate_entries if duplicate_key in entry]
        # check if force_nag set and if not, has key already been notified to the end user.
        if force_nag or duplicate_key not in ALREADY_NAGGED_DUP_KEYS:
            throw_warning(
                "Lookup value '{0}' was seen two or more times. "
                "It cannot be auto-referenced. To use, please remove duplicates in the CloudGenix controller, or "
                "reference it explicitly by the actual value: ".format(duplicate_key), matching_entries)
            # we've now notified, add to notified list.
            ALREADY_NAGGED_DUP_KEYS.append(duplicate_key)
    return lookup_dict


def extract_items(resp_object, error_label=None, id_key='id'):
    """
    Extract items (taken from cloudgenix_config)
    :param resp_object: CloudGenix Extended Requests.Response object.
    :param error_label: Optional text to describe operation on error.
    :param id_key: ID key, default 'id'
    :return: list of 'items' objects, list of IDs of objects.
    """
    items = resp_object.cgx_content.get('items')

    if resp_object.cgx_status and items is not None:
        # extract ID list
        id_list = []
        for item in items:
            item_id = item.get(id_key)
            if item_id is not None:
                id_list.append(item_id)

        # return data
        return items, id_list

    else:
        if error_label is not None:
            throw_error("Unable to cache {0}.".format(error_label), resp_object)
            return [], []
        else:
            throw_error("Unable to cache {0}.".format(error_label), resp_object)
            return [], []


def extract_tags(cgx_dict):
    """
    This function looks at a CloudGenix config object, and gets tags.
    Can use native tags (if supported by object) or hashtags in description.
    :param cgx_dict: CloudGenix config dict, expects "tags" or "description" keys supported in root.
    :return: list of tags present.
    """
    # check for existance of "tags" key
    if "tags" in cgx_dict:
        # tags exist, return them.
        tags = cgx_dict.get("tags", [])
        if tags is None:
            tags = []
    else:
        tags = []

    # need to also check hashtags in description.
    description = cgx_dict.get("description", "")
    # check for None.
    if description is None:
        description = ""
    # select all hashtags in description text, space or \n seperated, strip hash,
    # and no empty tags (ensure string not "" after lstrip).
    hashtags = [tag.lstrip('#') for tag in description.split() if tag.startswith("#") and tag.lstrip("#")]

    # return unique tags from both sources.
    return list(set(tags + hashtags))


def extract_ips(cgx_object):
    """
    Look for IPs in various spots in a CGX config dict.
    :param cgx_object: CloudGenix config dict
    :return: list of any IP strings found.
    """
    return_list = []
    # interfaces / LAN Networks
    ipv4_config = cgx_object.get('ipv4_config')
    if ipv4_config and isinstance(ipv4_config, dict):
        # static_config - address under "address"
        static_config = ipv4_config.get('static_config')
        if static_config and isinstance(static_config, dict):
            address = static_config.get('address')
            if address and isinstance(address, (str, bytes)):
                return_list.append(address)

        # default_routers - list right here
        default_routers = ipv4_config.get('default_routers')
        if default_routers and isinstance(default_routers, list):
            return_list.extend(default_routers)

        # prefixes - list right here.
        prefixes = ipv4_config.get('prefixes')
        if prefixes and isinstance(prefixes, list):
            return_list.extend(prefixes)

    # Static Routes
    destination_prefix = cgx_object.get('destination_prefix')
    if destination_prefix and isinstance(destination_prefix, (str, bytes)):
        return_list.append(destination_prefix)

    return return_list


def site_items_with_tag(sdk, site, tag, site_id2n):
    """
    Get all items with tag, return list of str.
    :param sdk: Authenticated CloudGenix SDK
    :param site: Site ID
    :param tag: Tag String
    :param site_id2n: Site ID -> Name map
    :return: List of Strings
    """
    return_list = []

    # Get LAN Networks
    lannetworks_resp = sdk.get.lannetworks(site)
    lannetworks_cache, _ = extract_items(lannetworks_resp, 'lannetworks')

    # lannetwork name
    lannetwork_id2n = build_lookup_dict(lannetworks_cache, key_val='id', value_val='name')

    # check LAN Networks next
    for lannetwork in lannetworks_cache:
        lannetwork_id = lannetwork.get('id')
        tags = extract_tags(lannetwork)
        if tag in tags:
            # found match
            object_ips = extract_ips(lannetwork)

            # for each IP, add entry in return_list
            for entry in object_ips:
                return_list.append("{0} # Site: {1} LAN Network: {2}"
                                   "".format(entry,
                                             site_id2n.get(site, site),
                                             lannetwork_id2n.get(lannetwork_id, lannetwork_id)))

    return return_list


def element_items_with_tag(sdk, site, element, tag, site_id2n, element_id2n):
    """
    Get all items with tag, return list of str.
    :param sdk: Authenticated CloudGenix SDK
    :param site: Site ID
    :param element: Element ID
    :param tag: Tag String
    :param site_id2n: Site ID -> Name map
    :param element_id2n: Element ID -> Name map
    :return: List of Strings
    """
    return_list = []

    # Get Static Routes
    staticroutes_resp = sdk.get.staticroutes(site, element)
    staticroutes_cache, _ = extract_items(staticroutes_resp, 'staticroutes')

    # Get Interfaces
    interfaces_resp = sdk.get.interfaces(site, element)
    interfaces_cache, _ = extract_items(interfaces_resp, 'interfaces')

    # Interface name
    interface_id2n = build_lookup_dict(interfaces_cache, key_val='id', value_val='name')

    # check static routes first.
    for route in staticroutes_cache:
        staticroute_id = route.get('id')
        tags = extract_tags(route)
        if tag in tags:
            # found match
            object_ips = extract_ips(route)

            # for each IP, add entry in return_list
            for entry in object_ips:
                return_list.append("{0} # Site: {1} Element: {2} Static Route: {3}"
                                   "".format(entry,
                                             site_id2n.get(site, site),
                                             element_id2n.get(element, element),
                                             staticroute_id))

    # check Interfaces Last
    for interface in interfaces_cache:
        interface_id = interface.get('id')
        tags = extract_tags(interface)
        if tag in tags:
            # found match
            object_ips = extract_ips(interface)

            # for each IP, add entry in return_list
            for entry in object_ips:
                return_list.append("{0} # Site: {1} Element: {2} Interface: {3}"
                                   "".format(entry,
                                             site_id2n.get(site, site),
                                             element_id2n.get(element, element),
                                             interface_id2n.get(interface_id, interface_id)))

    return return_list

####
#
# End custom modifiable code
#
####


# Start the script.
def go():
    """
    Stub script entry point. Authenticates CloudGenix SDK, and gathers options from command line to run do_site()
    :return: No return
    """

    # Parse arguments
    parser = argparse.ArgumentParser(description="{0} ({1})".format(GLOBAL_MY_SCRIPT_NAME, GLOBAL_MY_SCRIPT_VERSION))

    ####
    #
    # Add custom cmdline argparse arguments here
    #
    ####

    custom_group = parser.add_argument_group('parser_args', 'Parsing / Output Arguments')
    custom_group.add_argument("--output", "-O", help="Output File (default is './tagname.txt'",
                              default=None, type=str)
    custom_group.add_argument("--tag", "-T", help="Tag to search for.", required=True)

    ####
    #
    # End custom cmdline arguments
    #
    ####

    # Standard CloudGenix script switches.
    controller_group = parser.add_argument_group('API', 'These options change how this program connects to the API.')
    controller_group.add_argument("--controller", "-C",
                                  help="Controller URI, ex. https://api.elcapitan.cloudgenix.com",
                                  default=None)

    login_group = parser.add_argument_group('Login', 'These options allow skipping of interactive login')
    login_group.add_argument("--email", "-E", help="Use this email as User Name instead of cloudgenix_settings.py "
                                                   "or prompting",
                             default=None)
    login_group.add_argument("--password", "-PW", help="Use this Password instead of cloudgenix_settings.py "
                                                       "or prompting",
                             default=None)
    login_group.add_argument("--insecure", "-I", help="Do not verify SSL certificate",
                             action='store_true',
                             default=False)
    login_group.add_argument("--noregion", "-NR", help="Ignore Region-based redirection.",
                             dest='ignore_region', action='store_true', default=False)

    debug_group = parser.add_argument_group('Debug', 'These options enable debugging output')
    debug_group.add_argument("--sdkdebug", "-D", help="Enable SDK Debug output, levels 0-2", type=int,
                             default=0)

    args = vars(parser.parse_args())

    sdk_debuglevel = args["sdkdebug"]

    # Build SDK Constructor
    if args['controller'] and args['insecure']:
        sdk = cloudgenix.API(controller=args['controller'], ssl_verify=False)
    elif args['controller']:
        sdk = cloudgenix.API(controller=args['controller'])
    elif args['insecure']:
        sdk = cloudgenix.API(ssl_verify=False)
    else:
        sdk = cloudgenix.API()

    # check for region ignore
    if args['ignore_region']:
        sdk.ignore_region = True

    # SDK debug, default = 0
    # 0 = logger handlers removed, critical only
    # 1 = logger info messages
    # 2 = logger debug messages.

    if sdk_debuglevel == 1:
        # CG SDK info
        sdk.set_debug(1)
    elif sdk_debuglevel >= 2:
        # CG SDK debug
        sdk.set_debug(2)

    # login logic. Use cmdline if set, use AUTH_TOKEN next, finally user/pass from config file, then prompt.
    # figure out user
    if args["email"]:
        user_email = args["email"]
    elif CLOUDGENIX_USER:
        user_email = CLOUDGENIX_USER
    else:
        user_email = None

    # figure out password
    if args["password"]:
        user_password = args["password"]
    elif CLOUDGENIX_PASSWORD:
        user_password = CLOUDGENIX_PASSWORD
    else:
        user_password = None

    # check for token
    if CLOUDGENIX_AUTH_TOKEN and not args["email"] and not args["password"]:
        sdk.interactive.use_token(CLOUDGENIX_AUTH_TOKEN)
        if sdk.tenant_id is None:
            print("AUTH_TOKEN login failure, please check token.")
            sys.exit(1)

    else:
        while sdk.tenant_id is None:
            sdk.interactive.login(user_email, user_password)
            # clear after one failed login, force relogin.
            if not sdk.tenant_id:
                user_email = None
                user_password = None

    ####
    #
    # Do your custom work here, or call custom functions.
    #
    ####

    # sites
    sites_resp = sdk.get.sites()
    sites_cache, _ = extract_items(sites_resp, 'sites')

    # elements
    elements_resp = sdk.get.elements()
    elements_cache, _ = extract_items(elements_resp, 'elements')

    # name to ID maps
    # sites name
    sites_id2n = build_lookup_dict(sites_cache, key_val='id', value_val='name')

    # element name
    elements_id2n = build_lookup_dict(elements_cache, key_val='id', value_val='name')

    ip_output = []

    # enumerate all sites
    print("Searching {0} Sites, please wait...".format(len(sites_cache)))
    for site in sites_cache:
        site_id = site.get('id')

        # get the items with the tag.
        ip_output.extend(site_items_with_tag(sdk, site_id, args['tag'], sites_id2n))

    # enumerate all elements
    print("Searching {0} Elements, please wait...".format(len(elements_cache)))
    for element in elements_cache:
        # check if bound to site, if not - skip.
        element_id = element.get('id')
        site_id = element.get('site_id')
        if not site_id:
            print("Element {0} not bound to a site. Skipping.".format(elements_id2n.get(element_id, element_id)))
            continue

        # get the items with the tag.
        ip_output.extend(element_items_with_tag(sdk, site_id, element_id, args['tag'], sites_id2n, elements_id2n))

    if not ip_output:
        # no results, exit
        throw_error("No Interfaces or Static routes with tag '{0}' found. Exiting without creating file."
                    "".format(args['tag']))
        sys.exit(1)

    else:
        if not args['output']:
            # no specified file, use tag.txt
            filename = "./{0}.txt".format(args['tag'])
        else:
            filename = args['output']

    print("Writing {0} found entries to {1}".format(len(ip_output), filename))
    with open(filename, 'w') as outputfile:
        outputfile.write("\n".join(ip_output))

    ####
    #
    # End custom work.
    #
    ####


if __name__ == "__main__":
    go()
