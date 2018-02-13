# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
import cryptography.hazmat
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.serialization import PublicFormat
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import os

privada = None

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

def criaAssinatura(idd):
    global privada
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    file = open(idd, "w")
    file.write(public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo).decode())
    file.close()
    privada = private_key

def assinar(gx, gy):
    global privada
    assinatura=privada.sign(
        gx+gy,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
            ),
        hashes.SHA256()
        )
    return assinatura

def verificar(msg, gx, gy):
    file = open("servidor", "r")
    pem = file.read()
    public_key = load_pem_public_key(pem.encode(), default_backend())
    try:
        public_key.verify(
            msg,
            gy+gx,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return 1
    except:
        print("Assinatura Inválida")
        return 0




@asyncio.coroutine
def tcp_echo_client(loop=None):
    if loop is None:
        loop = asyncio.get_event_loop()

    reader, writer = yield from asyncio.open_connection('127.0.0.1', 8888,
                                                        loop=loop)
    key = AESGCM.generate_key(bit_length=128)
    iid = yield from reader.read(256)

    #Receber os parametros 
    p = yield from reader.read(3000)

    g = yield from reader.read(3000)
    criaAssinatura(iid.decode())


    pn = dh.DHParameterNumbers(int(p.decode()), int(g.decode()))
    parameters = pn.parameters(default_backend())
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    writer.write(public_bytes)
    yield from writer.drain()

    #Receber a public key dele
    public_key2 = yield from reader.read(3000)
    partner_pk = load_pem_public_key(public_key2, default_backend())
    shared_key = private_key.exchange(partner_pk)

    assinatura = assinar(public_bytes, public_key2)
    writer.write(assinatura)

    assinatura_partner = yield from reader.read(3000)
    if(len(assinatura_partner)!=0):
        res = verificar(assinatura_partner,public_bytes, public_key2)
        if res == 0:
            writer.write(b"")
            yield from writer.drain()


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