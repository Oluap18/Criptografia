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
from OpenSSL import crypto
import os

global privada

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

def assinar(gx, gy, p12):
    privada = p12.get_privatekey()
    private_key = privada.to_cryptography_key()
    assinatura=private_key.sign(
        gx+gy,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
            ),
        hashes.SHA256()
        )
    return assinatura

def verificar(msg, gx, gy, cert):
    public = cert.get_pubkey()
    public_key = public.to_cryptography_key()
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

def verify_chain_of_trust(certificate):
    #Carregar o ficheiro da CA intermédia
    cert_int = crypto.load_certificate(crypto.FILETYPE_PEM,
                                           open('./root/ca/intermediate/certs/intermediate.cert.pem', "rb").read())
    #Converter CA.cer em CA.pem
    trusted_cert_pem_int = crypto.dump_certificate(crypto.FILETYPE_PEM, cert_int)

    cert_root = crypto.load_certificate(crypto.FILETYPE_PEM,
                                           open('./root/ca/certs/ca.cert.pem', "rb").read())
    #Converter CA.cer em CA.pem
    trusted_cert_pem_root = crypto.dump_certificate(crypto.FILETYPE_PEM, cert_root)

    # Create and fill a X509Sore with trusted certs
    store = crypto.X509Store()
 
    trusted_cert_root = crypto.load_certificate(crypto.FILETYPE_PEM, trusted_cert_pem_root)
    store.add_cert(trusted_cert_root)
    
    trusted_cert_int = crypto.load_certificate(crypto.FILETYPE_PEM, trusted_cert_pem_int)
    store.add_cert(trusted_cert_int)

    # Create a X590StoreContext with the cert and trusted certs
    # and verify the the chain of trust
    store_ctx = crypto.X509StoreContext(store, certificate)
    # Returns None if certificate can be validated
    result = store_ctx.verify_certificate()

    if result is None:
        print("OK")
        return True
    else:
        print("ERRO")
        return False


@asyncio.coroutine
def tcp_echo_client(loop=None):
    if loop is None:
        loop = asyncio.get_event_loop()

    reader, writer = yield from asyncio.open_connection('127.0.0.1', 8888,
                                                        loop=loop)
    key = AESGCM.generate_key(bit_length=128)

    #Receber os parametros 
    p = yield from reader.read(3000)

    g = yield from reader.read(3000)


    pn = dh.DHParameterNumbers(int(p.decode()), int(g.decode()))
    parameters = pn.parameters(default_backend())
    private_key = parameters.generate_private_key()

    #Receber a public key dele
    public_key2 = yield from reader.read(3000)
    partner_pk = load_pem_public_key(public_key2, default_backend())

    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    writer.write(public_bytes)
    yield from writer.drain()

    #Fazer load do p12
    p12 = crypto.load_pkcs12(open("Cliente.p12", 'rb').read(), "secretpassword")
    assinatura = assinar(public_bytes, public_key2, p12)
    writer.write(assinatura)
    yield from writer.drain()

    certificate = p12.get_certificate()
    cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, certificate)
    writer.write(cert_pem)
    yield from writer.drain()

    shared_key = private_key.exchange(partner_pk)

    assinatura_partner = yield from reader.read(256)
    certificate_part = yield from reader.read(3000)
    certificate_part = crypto.load_certificate(crypto.FILETYPE_PEM, certificate_part)
    if(len(assinatura_partner)!=0):
        if(verify_chain_of_trust(certificate_part)==True):
            res = verificar(assinatura_partner,public_bytes, public_key2, certificate_part)
            if res == 0:
                writer.write(b"")
                yield from writer.drain()
            else:
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