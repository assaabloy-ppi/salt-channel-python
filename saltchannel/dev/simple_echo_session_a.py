import os
import logging
from .client_server_a import SessionA

CLIENT_SEND_LOOPS = 10


class SimpleEchoSessionA(SessionA):
    """Client session + server session asyncio coroutines implementing simplest echo protocol
    """

    async def server_session(self, reader, writer):
        """"""
        addr = writer.get_extra_info('peername')
        logging.info("SRV accepted connection from: {:s}".format(str(addr)))

        while not reader.at_eof():
            data = await reader.read_msg()
            if not data:
                logging.info("SRV received empty msg = client requested session end")
                break
            logging.info("<-- SRV Received: '{:s}' from: {:s}".format(data.hex(), str(addr)))
            writer.write_msg(data)
            logging.info("--> SRV Send:     '{:s}'".format(data.hex()))

        await writer.drain()
        logging.info("SRV closing connection")
        writer.close()

    async def client_session(self, reader, writer):
        """"""
        msg = os.urandom(6)
        addr = writer.get_extra_info('peername')
        for i in range(CLIENT_SEND_LOOPS):
            logging.info("--> CLIENT Send:     '{:s}'".format(msg.hex()))
            writer.write_msg(msg)
            data = await reader.read_msg()
            logging.info("<-- CLIENT Received: '{:s}' from: {:s}".format(data.hex(), str(addr)))

        # empty msg mean session end
        writer.write_msg(b'')
        await writer.drain()

        logging.info('Client closing the socket')
        writer.close()