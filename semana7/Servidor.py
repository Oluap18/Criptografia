# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
from Crypto.Cipher import ChaCha20

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import os
import base64

conn_cnt = 0
#gerar o salt
salt = os.urandom(16)


class ServerWorker(object):
    """ Classe que implementa a funcionalidade do SERVIDOR. """
    def __init__(self, cnt):
        self.id = cnt

    def respond(self, msg, peername):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = kdf.derive(msg[:8])
        cifra = ChaCha20.new(key=key, nonce=msg[8:16])

        """ Processa uma mensagem (enviada pelo CLIENTE)"""
        assert len(msg)>0, "mensagem vazia!!!"
        decript = cifra.decrypt(msg[16:])
        if not (decript.decode()): return decript.decode()
        print('%d : %r' % (self.id,decript.decode()))
        return msg


@asyncio.coroutine
def handle_echo(reader, writer):
    global kdf
    global conn_cnt
    conn_cnt +=1

    #Faze setup
    ident = "Cliente"+str(conn_cnt)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = kdf.derive(ident.encode())
    writer.write(ident.encode()+key)
    yield from writer.drain()

    srvwrk = ServerWorker(conn_cnt)
    
    data = yield from reader.read(200)
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

run_server()