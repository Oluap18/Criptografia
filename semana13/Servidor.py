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

conn_cnt = 0
privada = None

class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt, aesgcm):
        """ Construtor da classe. """
        self.id = cnt
        self.aesgcm = aesgcm
    def respond(self, msg, peername):
        """ Processa uma mensagem (enviada pelo CLIENTE)"""
        assert len(msg)>0, "mensagem vazia!!!"
        decript = self.aesgcm.decrypt(msg[:12], msg[12:], None)
        print('%d : %r' % (self.id,decript.decode()))
        return msg

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


#Alice
@asyncio.coroutine
def handle_echo(reader, writer):
    global conn_cnt
    global parameters
    conn_cnt +=1

    #Gerar a chave
    p = parameters.parameter_numbers().p
    writer.write(str(p).encode())
    yield from writer.drain()

    g = parameters.parameter_numbers().g
    writer.write(str(g).encode())
    yield from writer.drain()

    #Enviar a public key
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    public_bytes = public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
    writer.write(public_bytes)
    yield from writer.drain()

    #Receber a public key dele, assim como a assinatura e o certificado
    public_key2 = yield from reader.read(3000)
    partner_pk = load_pem_public_key(public_key2, default_backend())
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
                #Enviar a assinatura assim como o certificado do servidor
                p12 = crypto.load_pkcs12(open("Servidor.p12", 'rb').read(), "secretpassword")
                assinatura = assinar(public_bytes, public_key2, p12)
                writer.write(assinatura)
                yield from writer.drain()
                certificate = p12.get_certificate()
                cert_pem = crypto.dump_certificate(crypto.FILETYPE_PEM, certificate)
                writer.write(cert_pem)
                yield from writer.drain()


                #Gerar a chave
                aesgcm = AESGCM(shared_key[:32])
                srvwrk = ServerWorker(conn_cnt, aesgcm)
                data = yield from reader.read(100)
                while True:
                    if data[:1]==b'E': break
                    if not data: continue
                    addr = writer.get_extra_info('peername')
                    res = srvwrk.respond(data[1:], addr)
                    if not res: break
                    res = b'M'+res
                    writer.write(res)
                    yield from writer.drain()
                    data = yield from reader.read(100)
                print("[%d]" % srvwrk.id)
                writer.close()


def run_server():
    loop = asyncio.get_event_loop()
    coro = asyncio.start_server(handle_echo, '127.0.0.1', 8888, loop=loop)
    server = loop.run_until_complete(coro)
    # Serve requests until Ctrl+C is pressed
    print('Serving on {}'.format(server.sockets[0].getsockname()))
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    # Close the server
    server.close()
    loop.run_until_complete(server.wait_closed())
    loop.close()
    print('FINISHED!')


opt = input('Use test parameters? [Y/N]:  ')
if opt == 'Y' or opt == 'y':
    p = 25458351261674853333113413813876842978592478361112693440797061749361721215237296095637937794945801435912890198180891879875356222321508496098840870138362725856211912037217919297854841097340103981280265067779936293625781416661654213494473978857604176440841784758451488107960651207839990395951595478670869300705857239773186239617111085952480472701998362768652956825857129737943512035921567296012848974042903614926900264942429349884732479699826010244506769610203173698012465166524231898060075415692077642070338051307926649195107293068918007679179703149083782079252179788228052956157628616607790215500188673302590270419323
    g = 2
    pn = dh.DHParameterNumbers(p, g)
    parameters = pn.parameters(default_backend())
else:
    parameters = dh.generate_parameters(generator=GENERATOR, key_size=2048, backend=default_backend())
run_server()