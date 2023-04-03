#Ex mode sender
from hashlib import md5
from base64 import b64decode
from base64 import b64encode

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

#create random aes symmetric key
aeskey = get_random_bytes(16) #16 bytes = 128bit encryption

#get recipients public rsa key
with open('rpub.pem', 'rb') as f:
    pubkey= f.read()

# create rsa key
rsakey = RSA.importKey(pubkey)

# create rsacipher
rsacipher = PKCS1_OAEP.new(rsakey)

# creating aes key using encrypted rsacipher
e_aeskey = rsacipher.encrypt(aeskey)

#use aes key to encrypt file (AES symmetric)
with open('Text_message.txt', 'rb') as f:
    data = f.read()

aescipher = AES.new(aeskey, AES.MODE_EAX)
e_data, tag = aescipher.encrypt_and_digest(data)

# cipher = AES.new(key, AES.MODE_CBC)
# cipher_text = cipher.encrypt(pad(data, AES.block_size))
# iv = cipher.iv



#write both encrypted aes key and encrypted file to one bundled file
with open('bundle.enc', 'wb') as f:
    f.write(e_aeskey) #256 bytes
    f.write(aescipher.nonce) #16 bytes
    f.write(tag) #16 bytes
    f.write(e_data)


class AESCipher:
    def __init__(self, key):
        self.key = md5(key.encode('utf8')).digest()

    def encrypt(self, data):
        iv = get_random_bytes(AES.block_size)
        self.cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return b64encode(iv + self.cipher.encrypt(pad(data.encode('utf-8'), 
            AES.block_size)))

    def decrypt(self, data):
        raw = b64decode(data)
        self.cipher = AES.new(self.key, AES.MODE_CBC, raw[:AES.block_size])
        return unpad(self.cipher.decrypt(raw[AES.block_size:]), AES.block_size)


