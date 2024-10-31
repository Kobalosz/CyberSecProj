import secrets
import string
import re
import os

#Creation of the function to generate and create secure passwords as well as automatically validating their strength
Username = input('Please Enter your Username: ')

def passgen():
    passlen = int(input('Input Desired Password Length: '))

    def generate_password(length=passlen):
        characters = string.ascii_letters + string.digits + string.punctuation
        password = ''.join(secrets.choice(characters) for _ in range(length))
        xchar = ["|","`","¬","¦","~",]
        for char in password:
            for check in xchar:
                if char in xchar:
                    password = password.replace(char,'')
        return password

    password = generate_password()

    def is_strong_password(password):
        if len(password) <= 8:
            print('Insufficient Password length')
            return passgen()
        if not re.search("[a-z]", password):
            return False
        if not re.search("[A-Z]", password):
            return False
        # ... (add more checks for numbers, symbols, etc.)
        return password

    NewPass= is_strong_password(password)
    return NewPass
    
  
#the function that encrypts the created password complete with a encryption key

TestVar = passgen()



