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

conn_cnt = 0

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

    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    writer.write(public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo))
    yield from writer.drain()

    #Receber a public key dele
    public_key2 = yield from reader.read(3000)
    partner_pk = load_pem_public_key(public_key2, default_backend())
    shared_key = private_key.exchange(partner_pk)

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


parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

run_server()