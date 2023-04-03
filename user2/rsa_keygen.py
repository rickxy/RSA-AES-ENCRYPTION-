
from Crypto.Cipher import PKCS1_OAEP                                
from Crypto.PublicKey import RSA                                    
                                                                    
key=RSA.generate(2048)                                              
                                                                    
privkey= key.exportKey()                                            
pubkey= key.publickey().exportKey()                                 
                                                                    
with open('public.pem','wb') as f:                                  
    f.write(pubkey)

with open('private.pem','wb') as f:
    f.write(privkey)



# from cryptography.hazmat.primitives.asymmetric import rsa
# from cryptography.hazmat.primitives import serialization

# private_key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048
# )

# private_key_pass = b"your-password"

# encrypted_pem_private_key = private_key.private_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PrivateFormat.PKCS8,
#     encryption_algorithm=serialization.BestAvailableEncryption(private_key_pass)
# )

# pem_public_key = private_key.public_key().public_bytes(
#   encoding=serialization.Encoding.PEM,
#   format=serialization.PublicFormat.SubjectPublicKeyInfo
# )

# private_key_file = open("private.pem", "w")
# private_key_file.write(encrypted_pem_private_key.decode())
# private_key_file.close()

# public_key_file = open("public.pem", "w")
# public_key_file.write(pem_public_key.decode())
# public_key_file.close()


from Crypto.Cipher import PKCS1_OAEP                                
from Crypto.PublicKey import RSA                                    
                                                                    
key=RSA.generate(2048)                                              
                                                                    
privkey= key.exportKey()                                            
pubkey= key.publickey().exportKey()                                 
                                                                    
with open('public.pem','wb') as f:                                  
    f.write(pubkey)

with open('private.pem','wb') as f:
    f.write(privkey)
