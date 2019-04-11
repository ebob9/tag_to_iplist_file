Tag to IP List File
---------

Quick script to search for 'tag' across CloudGenix site objects, and export matching
IP/Prefix entries to a 'tag.txt' IP List file.

IP List file is intended to be compatible with Palo Alto Networks' External Dynamic List format: 
https://docs.paloaltonetworks.com/pan-os/8-1/pan-os-admin/policy/use-an-external-dynamic-list-in-policy/formatting-guidelines-for-an-external-dynamic-list/ip-address-list.html#

#### Example usage

```bash
edwards-mbp-pro:tag_to_iplist_file aaron$ ./tag_to_iplist.py -T test1
Searching 9 Sites, please wait...
Searching 9 Elements, please wait...
Writing 3 found entries to ./test1.txt
edwards-mbp-pro:tag_to_iplist_file aaron$ cat test1.txt 
20.0.0.1/29 # Site: AUTOMATION-LAB LAN Network: default_a-u-t-o-m-a-t-i-o-n-l-a-_748465088
1.1.1.0/24 # Site: AUTOMATION-LAB Element: AUTOMATION-BACKUP Static Route: 15549403969490079
10.10.255.10/29 # Site: AUTOMATION-LAB Element: AUTOMATION-BACKUP Interface: lan 1
edwards-mbp-pro:tag_to_iplist_file aaron$ 
```

#### Usage Info

```bash
usage: tag_to_iplist.py [-h] [--output OUTPUT] --tag TAG
                        [--controller CONTROLLER] [--email EMAIL]
                        [--password PASSWORD] [--insecure] [--noregion]
                        [--sdkdebug SDKDEBUG]

Tag to IP List (v1.0)

optional arguments:
  -h, --help            show this help message and exit

parser_args:
  Parsing / Output Arguments

  --output OUTPUT, -O OUTPUT
                        Output File (default is './tagname.txt'
  --tag TAG, -T TAG     Tag to search for.

API:
  These options change how this program connects to the API.

  --controller CONTROLLER, -C CONTROLLER
                        Controller URI, ex.
                        https://api.elcapitan.cloudgenix.com

Login:
  These options allow skipping of interactive login

  --email EMAIL, -E EMAIL
                        Use this email as User Name instead of
                        cloudgenix_settings.py or prompting
  --password PASSWORD, -PW PASSWORD
                        Use this Password instead of cloudgenix_settings.py or
                        prompting
  --insecure, -I        Do not verify SSL certificate
  --noregion, -NR       Ignore Region-based redirection.

Debug:
  These options enable debugging output

  --sdkdebug SDKDEBUG, -D SDKDEBUG
                        Enable SDK Debug output, levels 0-2
```