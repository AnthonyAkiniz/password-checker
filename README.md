# Password Checker
Python script that checks password against the pwnedpasswords.com api to see if it has been leaked.

# Requirements
* if don't have globally: pip install requests    
* if not sure, can verify with: pip list
* hashlib and sys come with Python 3

# Guide
Type password to check into password.txt file and save it in root folder.<br>
If using Python 3 run: py -3 password_checker.py password.txt<br>
Other Python versions, can run: python password_checker.py password.txt<br>

# Reading Data
"abc123" entered in password.txt as example.<br>
In terminal will see message as: abc123 was found 389k+ times.<br>
This means it found it in 389k+ password cracking lists, websites, databases, etc.<br>
