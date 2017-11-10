import struct
import logging
import asyncio
import asyncio.events as events
import asyncio.streams as streams
import asyncio.coroutines as coroutines
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from abc import ABCMeta, abstractmethod

####### place for now here - later move to separate module

class SaltChannelStreamWriter(streams.StreamWriter):
    def write_msg(self, msg):
        self.write(b''.join([struct.pack('<i', len(msg)), bytes(msg)]))

class SaltChannelStreamReader(streams.StreamReader):
    async def read_msg(self):
        msg_len = struct.unpack('<i', await self.readexactly(4))
        return b'' if not msg_len else await self.readexactly(msg_len[0])


class SaltChannelStreamReaderProtocol(streams.StreamReaderProtocol):
    def connection_made(self, transport):
        self._stream_reader.set_transport(transport)
        if self._client_connected_cb is not None:
            self._stream_writer = SaltChannelStreamWriter(transport, self,
                                                  self._stream_reader,
                                                  self._loop)
            res = self._client_connected_cb(self._stream_reader,
                                            self._stream_writer)
            if coroutines.iscoroutine(res):
                self._loop.create_task(res)

    def data_received(self, data):
        self._stream_reader.feed_data(data)

async def open_saltchannel_connection(host=None, port=None, *, loop=None, limit=streams._DEFAULT_LIMIT, **kwds):
    if loop is None:
        loop = events.get_event_loop()
    reader = SaltChannelStreamReader(limit=limit, loop=loop)
    protocol = SaltChannelStreamReaderProtocol(reader, loop=loop)
    transport, _ = await loop.create_connection(lambda: protocol, host, port, **kwds)
    writer = SaltChannelStreamWriter(transport, protocol, reader, loop)
    return reader, writer

async def start_saltchannel_server(client_connected_cb, host=None, port=None, *,
                                   loop=None, limit=streams._DEFAULT_LIMIT, **kwds):
    if loop is None:
        loop = events.get_event_loop()

    def factory():
        reader = SaltChannelStreamReader(limit=limit, loop=loop)
        protocol = SaltChannelStreamReaderProtocol(reader, client_connected_cb,
                                        loop=loop)
        return protocol

    return await loop.create_server(factory, host, port, **kwds)

#######


class SessionA(metaclass=ABCMeta):
    """Client session + server session asyncio coroutines"""

    @abstractmethod
    async def server_session(self, reader, writer):
        pass

    @abstractmethod
    async def client_session(self, reader, writer):
        pass

# To work with multiprocessing MUST be top-level (asyncio limitation?)
SERVER = None
LOOP = None

class ClientServerPairA:
    def __init__(self, session, client_num=1):
        self.session = session
        self.is_alive = False
        self.is_session_active = False
        self.client_num = client_num

    async def _client_session_wrap(self, loop=None):
        reader, writer = await open_saltchannel_connection('127.0.0.1', 8888, loop=loop)
        await self.session.client_session(reader, writer)


    def _spawn_client_process(self):
        new_loop = asyncio.new_event_loop()
        asyncio.set_event_loop(new_loop)
        new_loop.run_until_complete(self._client_session_wrap(loop=new_loop))
        new_loop.close()

    async def spawn_clients_and_wait(self, loop=None):
        futures = [asyncio.ensure_future(
            loop.run_in_executor(ProcessPoolExecutor(max_workers=self.client_num+1), self._spawn_client_process))
            for x in range(self.client_num)]
        while futures:
            done, futures = await asyncio.wait(futures, loop=loop, return_when=asyncio.ALL_COMPLETED)
            for f in done:
                await f

    def start_server(self):
        global LOOP, SERVER
        LOOP = asyncio.get_event_loop()
        coro = start_saltchannel_server(self.session.server_session, '127.0.0.1', 8888, loop=LOOP)
        SERVER = LOOP.run_until_complete(coro)
        logging.info('Serving on {}'.format(SERVER.sockets[0].getsockname()))

    def run_sessions(self):
        global LOOP
        self.is_session_active = True
        try:
            LOOP.run_until_complete(self.spawn_clients_and_wait(loop=LOOP))
        except KeyboardInterrupt:
            pass

    def stop_server(self):
        global LOOP, SERVER
        logging.info("Shutting down server...")
        SERVER.close()
        LOOP.run_until_complete(SERVER.wait_closed())
        LOOP.close()
        logging.info("Server stopped.")