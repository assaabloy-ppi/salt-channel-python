"""Example session data; used as an appendix to theSalt Channel v2 specification.
An executable class that outputs data needed to reproduce a simple Salt Channel session.
This is asyncio-based version of 'example_session_data.py' """

import os
import sys
import logging
import time

from .client_server_a import ClientServerPairA

# Log all to stdout
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("%(relativeCreated)06d - pid:%(process)s - %(message)s"))
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(logging.INFO)

CLIENT_NUM = 1

from .client_server_a import SessionA
from saltchannel.channel_a  import AsyncioChannel


class ExampleSessionA(SessionA):
    """Client session + server sessions asyncio coroutines implementing simplest echo protocol
    """

    async def server_session(self, reader, writer):
        """"""
        addr = writer.get_extra_info('peername')
        logging.info("SRV accepted connection from: {:s}".format(str(addr)))

        ch = AsyncioChannel(reader, writer)


        while not reader.at_eof():
            data = await ch.read()
            if not data:
                logging.info("SRV received empty msg = client requested session end")
                break
            logging.info("<-- SRV Received: '{:s}' from: {:s}".format(data.hex(), str(addr)))
            await ch.write(data)
            logging.info("--> SRV Send:     '{:s}'".format(data.hex()))

        logging.info("SRV closing connection")
        await ch.close()

    async def client_session(self, reader, writer):
        """"""
        ch = AsyncioChannel(reader, writer)

        msg = os.urandom(6)
        addr = writer.get_extra_info('peername')
        for i in range(1):
            logging.info("--> CLIENT Send:     '{:s}'".format(msg.hex()))
            await ch.write(msg)
            data = await ch.read()
            logging.info("<-- CLIENT Received: '{:s}' from: {:s}".format(data.hex(), str(addr)))

        # empty msg mean session end
        await ch.write(b'')
        logging.info('Client closing the socket')
        await ch.close()


def main():
    print()

    csa = ClientServerPairA(ExampleSessionA(), CLIENT_NUM)
    csa.start_server()

    t0 = time.perf_counter()
    csa.run_sessions()
    logging.info("All client session runtime: {:.6f} ms".format(1000*(time.perf_counter()-t0)))

    csa.stop_server()


if __name__ == '__main__':
    main()
