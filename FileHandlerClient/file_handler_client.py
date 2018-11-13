import json
import requests
import random
import string
import sys

from pyDes import des, PAD_PKCS5
from os import chmod
from Crypto.PublicKey import RSA

from config import FILE_DISTRIBUTOR_ADDRESS


class FileHandlerClient(object):
    def __init__(self):
        self.generate_rsa_keypair()

    def generate_rsa_keypair(self):
        key = RSA.generate(2048)
        with open("private.key", 'w+') as private_key_file:
            chmod("private.key", 0600)
            private_key_file.write(key.exportKey('PEM'))
        pubkey = key.publickey()
        self.publish_public_key(pubkey.exportKey('PEM'))
        with open("public.key", 'w+') as public_key_file:
            public_key_file.write(pubkey.exportKey('PEM'))

    def publish_public_key(self, public_key):
        publish_req = requests.post('{}/publish_key'.format(FILE_DISTRIBUTOR_ADDRESS), json={'public_key': public_key})
        if publish_req.status_code == 201:
            print "INFO: Key published successfully!"
        else:
            print "ERROR: Key publish operation failed!"
            print publish_req.status_code


file_handler_client = FileHandlerClient()

# filepath = raw_input("Enter file path to encrypt: ")
filepath = 'test.txt'

if not filepath.endswith('.txt'):
    print "ERROR: Only 'txt' format supported. Found '{}'\nExiting now...!".format(filepath.rsplit('.')[-1])
    sys.exit()
try:
    with open(filepath, 'r') as file_to_encrypt:
        data = file_to_encrypt.read()

except (OSError, IOError) as ex:
    print "ERROR: Unable to load {} contents...".format(filepath)
    sys.exit()

symmetric_key = ''.join(random.choice(string.ascii_letters) for _ in range(8))
print symmetric_key

d = des(symmetric_key)
cipher_text = d.encrypt(data, padmode=PAD_PKCS5)


print "Ciphered: "
print cipher_text


print "Deciphered: "
plain = d.decrypt(cipher_text, padmode=PAD_PKCS5)
print plain

receivers_req = requests.get('{}/get_known_hosts'.format(FILE_DISTRIBUTOR_ADDRESS))
print receivers_req.status_code
if receivers_req.status_code == 200:
    print "The following receiver's found: "
    for index, receiver_addr in enumerate(json.loads(receivers_req.content).keys()):
        print '{index}) {ip}'.format(index=index + 1, ip=receiver_addr)


