# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import cryptography.hazmat
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os

class Client:
    """ Classe que implementa a funcionalidade de um CLIENTE. """
    def __init__(self, name, aesgcm):
        """ Construtor da classe. Recebe o nome do cliente """
        self.name = name
        self.aesgcm = aesgcm
    def initmsg(self):
        nonce = os.urandom(12)
        """ Mensagem inicial """
        str = "Hello from %r!" % (self.name)
        return nonce +  self.aesgcm.encrypt(nonce, str.encode(), None)
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

    reader, writer = yield from asyncio.open_connection('127.0.0.1', 8888,
                                                        loop=loop)
    key = AESGCM.generate_key(bit_length=128)

    #Receber os parametros 
    p = yield from reader.read(3000)
    yield from writer.drain()

    g = yield from reader.read(3000)
    yield from writer.drain()

    pn = dh.DHParameterNumbers(int(p), int(g))
    parameters = pn.parameters(default_backend())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    writer.write(public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    yield from writer.drain()

    #Receber a public key dele
    public_key2 = yield from reader.read(3000)
    partner_pk = load_pem_public_key(public_key2, default_backend())
    shared_key = private_key.exchange(partner_pk)
    print(shared_key)


    data = b'S'
    #Gerar a chave
    aesgcm = AESGCM(shared_key[:32])
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