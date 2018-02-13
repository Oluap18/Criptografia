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
        filename = input("Introduza o nome do ficheiro a desencriptar: ")
    else:
        filename = sys.argv[1]

def verifica_HMAC(hmac, mac):
	try:
	  	hmac.verify(mac)
	  	return True
	except ValueError:
	  	return False

def desencripta(mensagem, salsaKey):
	msg_nonce = mensagem[:8]
	mensagemCifrada = mensagem[8:]
	cifra = Salsa20.new(salsaKey, nonce=msg_nonce)
	msgFinal = cifra.decrypt(mensagemCifrada)
	return msgFinal

password = input("Input Password:").encode("utf-8")

f_read = open(filename, "rb")
f_write = open(filename + "_decriptado", "w")

mensagem = f_read.read()
encriptada = mensagem[32:]

salt_r = open(filename + "_salt", "rb")
salt = salt_r.read()
salt_r.close()

kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=default_backend()
)

key = kdf.derive(password)


hmac = HMAC.new(key, digestmod=SHA256)
hmac.update(encriptada)

if(verifica_HMAC(hmac, mensagem[:32]) == True):
	f_write.write(desencripta(encriptada, key).decode("utf-8"))
else:
	print("Mensagem Adulterada Ou Password Incorreta")