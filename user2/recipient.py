# hybrid eax mode recipient

from Crypto.Cipher import AES

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA

with open('bundle.enc', 'rb') as f:
    e_aeskey = f.read(256)
    #16 byte aes key becomes 256 bytes after rsa encryption
    nonce = f.read(16)
    tag = f.read(16)
    e_data = f.read()

with open('private.pem') as f:
    key = f.read()

# Creating an RSA from the private key
privkey = RSA.importKey(key)

rsacipher = PKCS1_OAEP.new(privkey)

# Decrypting the aes key
aeskey = rsacipher.decrypt(e_aeskey)
try:
    aescipher = AES.new(aeskey, AES.MODE_EAX, nonce)
    data = aescipher.decrypt_and_verify(e_data, tag)
except:
    print('Decryption or Authenticity failure')

with open('decrypted.txt', 'wb') as f:
    f.write(data)
