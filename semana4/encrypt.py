from Crypto.Cipher import Salsa20
from Crypto.Cipher import ARC4
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
import os
import base64

if __name__ == "__main__":
    import sys
    if len(sys.argv) <= 1:
        filename = input("Introduza nome do ficheiro a encriptar: ")
    else:
        filename = sys.argv[1]

def encript_salsa20(msg, salsakey):
	cifraI = Salsa20.new(salsakey)
	mensagem = cifraI.nonce + cifraI.encrypt(msg)
	return mensagem

def encript_HMAC(msg, hMacS):
	cifraS = HMAC.new(hMacS, digestmod=SHA256)
	cifraS.update(msg)
	mac = cifraS.digest()
	return mac


print("Nome do ficheiro a encriptar: %s\n" % filename)
file_r = open(filename,"r")
file_w = open(filename + "_encripted", "wb") 

mensagem = file_r.read().encode("utf-8")

password = input("Input Password:").encode("utf-8")

salt = os.urandom(16)

salt_w = open(filename + "_encripted_salt", "wb")
salt_w.write(salt)
salt_w.close()

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)

key = kdf.derive(password)


cifraS = encript_salsa20(mensagem, key)
mac = encript_HMAC(cifraS, key)

print(mac)


file_w.write(mac + cifraS)