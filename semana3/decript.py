from Crypto.Cipher import Salsa20
from Crypto.Cipher import ARC4
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

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
	cifra = Salsa20.new(key=salsaKey, nonce=msg_nonce)
	msgFinal = cifra.decrypt(mensagemCifrada)
	return msgFinal

salsaKey = b'Run You Fool, Join The Dark Side'
hMacS = b'You Shall Not Pass'

f_read = open(filename, "rb")
f_write = open(filename + "_decriptado", "w")

mensagem = f_read.read()
encriptada = mensagem[32:]

hmac = HMAC.new(hMacS, digestmod=SHA256)
hmac.update(encriptada)

if(verifica_HMAC(hmac, mensagem[:32]) == True):
	f_write.write(desencripta(encriptada, salsaKey).decode("utf-8"))
else:
	print("Mensagem Adulterada")