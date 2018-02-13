from Crypto.Cipher import Salsa20
from Crypto.Cipher import ARC4
from Crypto.Hash import HMAC, SHA256
from Crypto.Random import get_random_bytes

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

salsaKey = b'Run You Fool, Join The Dark Side'
hMacS = b'You Shall Not Pass'

cifraS = encript_salsa20(mensagem, salsaKey)
mac = encript_HMAC(cifraS, hMacS)


file_w.write(mac + cifraS)