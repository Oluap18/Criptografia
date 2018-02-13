# Código baseado em https://docs.python.org/3.6/library/asyncio-stream.html#tcp-echo-client-using-streams
import asyncio
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
        if not (decript.decode()): return decript.decode()
        print('%d : %r' % (self.id,decript.decode()))
        return msg


@asyncio.coroutine
def handle_echo(reader, writer):
    global key
    global conn_cnt
    conn_cnt +=1

    #gerar a key
    key = AESGCM.generate_key(bit_length=128)
    aesgcm = AESGCM(key)
    aad = b'authenticated but unencrypted data'
    #Enviar a chave para o cliente
    writer.write(key)
    yield from writer.drain()

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

run_server()