# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from Crypto.Cipher import ChaCha20
import os

class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self,name,  key):
        """ Construtor da classe. Recebe o nome do cliente """
        self.name = name
        self.key = key
    def initmsg(self):
        nonce = os.urandom(8)
        cipher = ChaCha20.new(key=self.key, nonce=nonce)
        """ Mensagem inicial """
        str = cipher.encrypt(b"Hello from %r!" % (self.name))
        return self.name.encode()+nonce + str
    def passKey(self, key):
        return key
    def respond(self, msg):
        """ Processa uma mensagem (enviada pelo SERVIDOR)
        Imprime a mensagem recebida e lê do teclado a
        resposta. """
        cifra = ChaCha20.new(key=self.key, nonce=msg[8:16])
        print('Received: %r' % cifra.decrypt(msg[16:]))
        
        #Encripta a nova mensagem
        new = input().encode()
        nonce = os.urandom(8)
        cifra2 = ChaCha20.new(key=self.key, nonce=nonce)
        new = cifra2.encrypt(new)
        return self.name.encode()+ nonce + new



@asyncio.coroutine
def tcp_echo_client(loop=None):
    if loop is None:
        loop = asyncio.get_event_loop()

    reader, writer = yield from asyncio.open_connection('127.0.0.1', 8888,
                                                        loop=loop)

    data = b'S'
    #Setup
    msgI = yield from reader.read(128)
    client = Client(msgI[:8].decode(), msgI[8:])
    
    msg = client.initmsg()
    while len(data)>0:
        if msg:
            msg = b'M' + msg
            writer.write(msg)
            if msg[:1] == b'E': break
            data = yield from reader.read(100)
            if len(data)>0 :
                msg = client.respond(data[1:])
            else:
                break
        else:
            break
    writer.write(b'E')
    print('Socket closed!')
    writer.close()


def run_client():
    loop = asyncio.get_event_loop()
    loop.run_until_complete(tcp_echo_client())


run_client()