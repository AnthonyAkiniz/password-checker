#########################################################################################
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
# * ################################################################################# * #
# * #                    Password Checker (pwnedpasswords.com API)                  # * #
# * #                         project by: Anthony Akiniz                            # * #
# * #                          github.com/anthonyakiniz                             # * #
# * ################################################################################# * #
# * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * #
#########################################################################################
# Password Checker Info:                                                                #
# Checks password against the pwnedpasswords.com api to see if it has been leaked.      #
#                                                                                       #
# Requirements:                                                                         #
# if don't have globally: pip install requests                                          #
# if not sure, can verify with: pip list                                                #
# hashlib and sys come with Python 3                                                    #
# documentation: https://pypi.org/project/requests                                      #
#                                                                                       #
# Guide:                                                                                #
# Type password to check into password.txt file and save it in root folder.             #
# if using Python 3 run: py -3 password_checker.py password.txt                         #
# other Python versions, can run: python password_checker.py password.txt               #
#                                                                                       #
# Reading Data (abc123 entered in password.txt as example):                             #
# In terminal will see message as: abc123 was found 389k+ times.                        #
# This means it found it in 389k password cracking lists, websites, databases, etc.     #
#########################################################################################

import sys
import hashlib
import requests


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    res = requests.get(url)
    if res.status_code != 200:
        raise RuntimeError(
            f'Error fetching: {res.status_code}, check the api and try again')
    return res


def get_password_leaks_count(hashes, hash_to_check):
    # Split all returned hashed password with ':' (hashes, count of leaks) by line
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0


def pwned_api_check(password):
    # Compile password in the hash sha1 method with utf8 format
    sha1password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    # Get all matches for the hashed (first5_char) data from the api
    response = request_api_data(first5_char)
    # Pass all responses from api and return the count of any matching combination with the tail
    return get_password_leaks_count(response, tail)


# Calls from a text file (more secure)
def read_password_txt(filename):
    with open(filename) as f:
        lines = [line.rstrip() for line in f]
        return lines


def main(args):
    for password in read_password_txt(args):
        count = pwned_api_check(password)
        if count:
            print(
                f'{password} was found {count} times... you should probably change your password!')
        else:
            print(f'{password} was NOT found. Carry on!')
    return 'done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1]))

# standard method calls individual passwords to check from the command line
# but pw gets stored in CLI memory when press up arrow, can recall it
# less secure than reading from text file so commented out
# def main(args):
#     for password in args:
#         count = pwned_api_check(password)
#         if count:
#             print(
#                 f'{password} was found {count} times... you should probably change your password!')
#         else:
#             print(f'{password} was NOT found. Carry on!')
#     return 'done!'


# if __name__ == '__main__':
#     sys.exit(main(sys.argv[1:]))
