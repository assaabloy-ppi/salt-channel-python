"""Example session data; used as an appendix to theSalt Channel v2 specification.
Outputs data needed to reproduce a simple Salt Channel session.
This is asyncio-based version of 'example_session_data.py' """

import sys
import logging
import time

from .client_server_a import ClientServerPairA
from .mitm_channel_a import MitmChannelA

# Log all to stdout
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("%(relativeCreated)06d - pid:%(process)s - %(message)s"))
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(logging.INFO)

CLIENT_NUM = 1

from .client_server_a import SessionA
from saltchannel.channel_a  import AsyncioChannel

from saltchannel.v2.salt_client_session_a import SaltClientSessionA
from saltchannel.v2.salt_server_session_a import SaltServerSessionA
from saltchannel.util.crypto_test_data import CryptoTestData
from saltchannel.exceptions  import ComException


class ExampleSessionA(SessionA):
    """Client session + server sessions asyncio coroutines implementing same protocol as:
    https://github.com/assaabloy-ppi/salt-channel/blob/master/src/saltchannel/dev/ExampleSessionData.java"""

    def __init__(self):
        self.server_sig_keypair = CryptoTestData.bSig
        self.server_enc_keypair = CryptoTestData.bEnc
        self.client_sig_keypair = CryptoTestData.aSig
        self.client_enc_keypair = CryptoTestData.aEnc


    async def server_session(self, reader, writer):
        """Server-side session implementation for basic handshake (async!)"""
        addr = writer.get_extra_info('peername')
        logging.info("SRV accepted connection from: {:s}".format(str(addr)))

        channel = AsyncioChannel(reader, writer)

        sssa = SaltServerSessionA(self.server_sig_keypair, channel)
        sssa.enc_keypair = self.server_enc_keypair
        sssa.buffer_m2 = False
        await sssa.handshake()
        await sssa.app_channel.write(await sssa.app_channel.read())  # echo once at app layer

        logging.info("SRV closing connection")
        channel.close()

    async def client_session(self, reader, writer):
        """Client-side session implementation for basic handshake (async!)"""
        ch = AsyncioChannel(reader, writer)
        channel = MitmChannelA(ch, log=logging.getLogger(__name__))  # maybe better to move this to client_server_a.py

        scsa = SaltClientSessionA(self.client_sig_keypair, channel)
        scsa.enc_keypair = self.client_enc_keypair
        scsa.buffer_M4 = False

        # print session initial details to stdout
        print("======== example_session_data.py ========")
        print("\nclient signature key pair:\n" + str(self.client_sig_keypair))
        print("\nclient encryption key pair:\n" + str(self.client_enc_keypair))
        print("\nserver signature key pair:\n" + str(self.server_sig_keypair))
        print("\nserver encryption key pair:\n" + str(self.server_enc_keypair))
        print("\n ----------------------- client <--> server --------------------------\n")

        await scsa.handshake()

        cnt_read0 = channel.counter_read  # it's possible with MitmChannel instances only!
        cnt_write0 = channel.counter_write  # it's possible with MitmChannel instances only!

        app_request = bytes([0x01, 0x05, 0x05, 0x05, 0x05, 0x05])
        await scsa.app_channel.write(app_request)
        app_response = await scsa.app_channel.read()

        cnt_read = channel.counter_read  # it's possible with MitmChannel instances only!
        cnt_write = channel.counter_write  # it's possible with MitmChannel instances only!

        # print results to stdout
        print("\n ---------------------------------------------------------------------\n")
        print("\nsession key: " + scsa.session_key.hex())
        print("app request: " + app_request.hex())
        print("app response: " + app_response.hex())

        print("\nclient --> server handshake bytes: ", cnt_write0)
        print("client <-- server handshake bytes: ", cnt_read0)
        print("client --> server total bytes: ", cnt_write)
        print("client <-- server total bytes: ", cnt_read)

        print("\nHANDSHAKE BYTES: ", cnt_write0 + cnt_read0)
        print("TOTAL BYTES: ", cnt_write + cnt_read)
        print("\n ---------------------------------------------------------------------\n")

        # empty msg mean session end
        await channel.write(b'')
        logging.info('Client closing the socket')
        channel.close()


def main():
    print()

    csa = ClientServerPairA(ExampleSessionA(), CLIENT_NUM)
    csa.start_server()

    t0 = time.perf_counter()
    csa.run_sessions()
    logging.info("Session runtime: {:.6f} ms".format(1000*(time.perf_counter()-t0)))

    csa.stop_server()


if __name__ == '__main__':
    main()
