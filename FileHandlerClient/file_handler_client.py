import json
import time
import requests
import random
import string
import sys

from base64 import b64encode, b64decode
from Crypto.Cipher import PKCS1_v1_5
from Crypto.PublicKey import RSA
from os import chmod
from pyDes import des, PAD_PKCS5

from config import FILE_DISTRIBUTOR_ADDRESS


class FileHandlerClient(object):
    def __init__(self):
        self.identity = None
        self.pub_key = None
        self.priv_key = None
        self.read_or_generate_rsa_keypair()

    def read_or_generate_rsa_keypair(self):
        try:
            with open("identity.txt", 'r') as id_file:
                self.identity = id_file.read()
            with open("private.key", 'r') as private_key_file:
                self.priv_key = private_key_file.read()
            with open("public.key", 'r') as public_key_file:
                self.pub_key = public_key_file.read()

            print "Identity '{}' dicovered successfully...\nLoading RSA keypair into memory...".format(self.identity)

        except IOError:
            self.identity = raw_input("Please_enter your identity: ")
            print "Identity created successfully!\n Generating RSA keypair..."
            with open("identity.txt", 'w+') as id_file:
                id_file.write(self.identity)

            key = RSA.generate(2048)
            with open("private.key", 'w+') as private_key_file:
                chmod("private.key", 0600)
                self.priv_key = key.exportKey('PEM')
                private_key_file.write(key.exportKey('PEM'))

            pubkey = key.publickey()
            self.pub_key = pubkey.exportKey('PEM')
            with open("public.key", 'w+') as public_key_file:
                public_key_file.write(pubkey.exportKey('PEM'))

            print 'Publishing public key on FileDistributor running @ {}'.format(FILE_DISTRIBUTOR_ADDRESS)
            self.publish_public_key()

    def publish_public_key(self):
        publish_req = requests.post('{}/publish_key'.format(FILE_DISTRIBUTOR_ADDRESS),
                                    json={'client_id': self.identity, 'public_key': self.pub_key})

        if publish_req.status_code == 201:
            print "INFO: Key published successfully!"
        else:
            print "ERROR: Key publish operation failed!"
            print publish_req.status_code


file_handler_client = FileHandlerClient()

print "\nFollowing client running modes are available: \n1) Sender mode\n2) Receiver mode\n"
running_mode = input("\nPlease select from above: ")

if running_mode == 1:
    #  Hard coding the Test file, Uncomment below line to send a file other than 'test.txt'
    # filepath = raw_input("Enter file path to encrypt: ")

    filepath = 'test.txt'
    split_filename = filepath.rsplit("/")
    filename = split_filename[1] if len(split_filename) > 1 else split_filename[0]

    if not filepath.endswith('.txt'):
        print "ERROR: Only 'txt' format supported. Found '{}'\nExiting now...!".format(filepath.rsplit('.')[-1])
        sys.exit()
    try:
        with open(filepath, 'r') as file_to_encrypt:
            data = file_to_encrypt.read()

    except (OSError, IOError) as ex:
        print "ERROR: Unable to load {} contents...".format(filepath)
        sys.exit()

    print "Generating 64-bit symmetric key..."
    symmetric_key = ''.join(random.choice(string.ascii_letters) for _ in range(8))
    print "Symmetric key: {}".format(symmetric_key)

    d = des(symmetric_key)
    cipher_text = d.encrypt(data, padmode=PAD_PKCS5)
    print "Encrypting '{}' with generated symmetric key...\n \nFetching public keys of receivers. . ".format(filename)

    receivers_req = requests.get('{}/get_known_hosts'.format(FILE_DISTRIBUTOR_ADDRESS))
    if not receivers_req.status_code == 200:
        print "ERROR: No receivers found on server!"
        sys.exit()

    receivers_list = json.loads(receivers_req.content)
    print "The following receiver's found: "
    for index, receiver_addr_pubkey_tuple in enumerate(receivers_list):
        print '{index}) {ip}'.format(index=index + 1, ip=receiver_addr_pubkey_tuple[0])

    while True:
        choice = input("\nPlease select a receiver from above: ")
        if 0 < choice <= (index + 1):
            break

    receiver = receivers_list[choice - 1]

    cipher = PKCS1_v1_5.new(RSA.importKey(receiver[1]))
    ciphered_symmetric_key = cipher.encrypt(symmetric_key)
    print "Enciphering symmetric key with '{}'s public key... ".format(receiver[0])

    print "Appending cipher text and ciphered key with delimitor 'HAMID_&_RAHEEL_DELIMITER'..."
    secure_file = 'HAMID_&_RAHEEL_DELIMITER'.join([cipher_text, ciphered_symmetric_key])
    b64_encoded_secure_file = b64encode(secure_file)
    send_file_req = requests.post('{}/upload_file'.format(FILE_DISTRIBUTOR_ADDRESS),
                                  json={'receiver': receiver[0], 'filename': filename,
                                        'file_contents': b64_encoded_secure_file})

    if send_file_req.status_code == 200:
        print "INFO: Encrypted file '{}' for receiver '{}' uploaded successfully!".format(filename, receiver[0])
    else:
        print "ERROR: Could not upload file!"
        print send_file_req.status_code

elif running_mode == 2:
    retries = 0
    while retries < 3:
        get_files_req = requests.get('{}/get_files'.format(FILE_DISTRIBUTOR_ADDRESS),
                                     params={'identity': file_handler_client.identity})
        if not get_files_req.status_code == 200:
            print "INFO: No files found!"
            sys.exit()

        elif get_files_req.status_code == 200:
            for file_ in json.loads(get_files_req.content):
                filename = file_['filename']
                sender = file_['sender']
                file_contents = file_['file_contents']

                print "File '{fname}' received from '{sender}'... Writing to 'newFile_{fname}'".format(fname=filename,
                                                                                                       sender=sender)

                b64_decoded_file_contents = b64decode(file_contents)
                cipher_text, encrypted_symmetric_key = b64_decoded_file_contents.split('HAMID_&_RAHEEL_DELIMITER')

                symmetric_key = PKCS1_v1_5.new(RSA.importKey(file_handler_client.priv_key)). \
                    decrypt(encrypted_symmetric_key, "ERROR")

                if symmetric_key == 'ERROR':
                    print "ERROR: Symmetric key decryption failed! Skipping file...."
                    continue

                print "Deciphering symmertic key... "

                d = des(symmetric_key)
                plain_text = d.decrypt(cipher_text, padmode=PAD_PKCS5)
                print "Deciphering file contents... "

                with open('newFile_{}'.format(filename), 'w+') as newly_downloaded_file:
                    newly_downloaded_file.write(plain_text)

                print "File contents successfully written to 'newFile_{}'".format(filename)

            break

        time.sleep(5)
        retries += 1
