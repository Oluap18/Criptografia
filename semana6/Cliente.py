# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self,name,  aesgcm):
        """ Construtor da classe. Recebe o nome do cliente """
        self.name = name
        self.aesgcm = aesgcm
    def initmsg(self):
        nonce = os.urandom(12)
        """ Mensagem inicial """
        str = self.aesgcm.encrypt(nonce, b"Hello from %r!" % (self.name), None)
        return nonce + str
    def passKey(self, key):
        return key
    def respond(self, msg):
        nonce = os.urandom(12)
        """ Processa uma mensagem (enviada pelo SERVIDOR)
        Imprime a mensagem recebida e lê do teclado a
        resposta. """
        print('Received: %r' % self.aesgcm.decrypt(msg[:12], msg[12:], None))
        new = input().encode()
        new = self.aesgcm.encrypt(nonce, new, None)
        return nonce + new



@asyncio.coroutine
def tcp_echo_client(loop=None):
    if loop is None:
        loop = asyncio.get_event_loop()

    #gerar a key
    key = AESGCM.generate_key(bit_length=128)
    aesgcm = AESGCM(key)
    reader, writer = yield from asyncio.open_connection('127.0.0.1', 8888,
                                                        loop=loop)

    data = b'S'
    #transição da chave
    key = yield from reader.read(128)
    aesgcm = AESGCM(key)

    client = Client("Cliente 1", aesgcm)
    
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