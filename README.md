# OpenVNC-Finder
Locate open VNC servers(by country) using online resources(Shodan and Censys) and take screenshots of them.

**Requirements**
This code runs on Python3. Additionally these packages are required:

*  requests 
*  argparse
*  vncdotool
*  cv2

**Usage**
Run `python3 extract.py` to see which arguments are required, and `python3 extract.py -h` for help on what they are.
An example usage would be: 
`python3 extract.py -c US -uC user:pass -uS user:pass -f US -k -p 3`

**Note**
Shodan limits searches, so if you see no output from it, just create and use a different account.
 
 **TODO**
- Add options for premium Censys and Shodan users, currently only works for basic users (2 pages for Shodan and might throw errors if exceeds Censys's limit)
- Tidy up the code, and fix some faults with exception handling and try to warn users of any limits the website has applied on their IP
