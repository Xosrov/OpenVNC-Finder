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

**Note**
Shodan limits searches, so if you see no output from it, just create and use a different account.
