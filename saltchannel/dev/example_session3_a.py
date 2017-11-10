"""Example session data 3; handshake, echo with AppPacket, echo+close with MultiAppPacket.
This is asyncio-based version of 'example_session3.py'
"""
import sys
import logging
import time

from .client_server_a import ClientServerPairA
from .mitm_channel import MitmChannel
from saltchannel.util.time import TimeKeeper

# Log all to stdout
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("%(relativeCreated)06d - pid:%(process)s - %(message)s"))
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(logging.INFO)

CLIENT_NUM = 1

from .client_server_a import SessionA
from saltchannel.channel  import AsyncioChannel

from saltchannel.v2.salt_client_session import SaltClientSession
from saltchannel.v2.salt_server_session import SaltServerSession
from saltchannel.util.crypto_test_data import CryptoTestData
from saltchannel.exceptions  import ComException


class OneTwoThreeTimeKeeper(TimeKeeper):
    def __init__(self):
        self.time = 0

    def get_first_time(self):
        self.time = 1
        return 1

    def get_time(self):
        self.time += 1
        return self.time


class ExampleSessionA(SessionA):
    """Client session + server sessions asyncio coroutines implementing same protocol as:
    https://github.com/assaabloy-ppi/salt-channel/blob/master/src/saltchannel/dev/ExampleSession3.java"""

    def __init__(self):
        self.server_sig_keypair = CryptoTestData.bSig
        self.server_enc_keypair = CryptoTestData.bEnc
        self.client_sig_keypair = CryptoTestData.aSig
        self.client_enc_keypair = CryptoTestData.aEnc

    async def server_session(self, reader, writer):
        """Server-side session implementation (async!)"""
        addr = writer.get_extra_info('peername')
        logging.info("SRV accepted connection from: {:s}".format(str(addr)))

        channel = AsyncioChannel(reader, writer)

        sss = SaltServerSession(self.server_sig_keypair, channel)
        sss.enc_keypair = self.server_enc_keypair
        sss.time_keeper = OneTwoThreeTimeKeeper()

        await sss.handshake()
        await sss.app_channel.write(await sss.app_channel.read())  # echo once at app layer
        data1 = await sss.app_channel.read()
        data2 = await sss.app_channel.read()
        await sss.app_channel.write(data1, data2, is_last=True)  # echo two application messages back, lastFlag is true

        if sss.app_channel.last:  # client do not plan to send something more
            logging.info("LastFlag detected in client's message. Server decides to close current connection.")

        logging.info("SRV closing connection")
        channel.close()

    async def client_session(self, reader, writer):
        """Client-side session implementation (async!)"""
        ch = AsyncioChannel(reader, writer)
        channel = MitmChannel(ch, log=logging.getLogger(__name__))  # maybe better to move this to client_server_a.py

        scs = SaltClientSession(self.client_sig_keypair, channel)
        scs.enc_keypair = self.client_enc_keypair
        scs.time_keeper = OneTwoThreeTimeKeeper()

        # print session initial details to stdout
        print("======== example_session3_a.py ========")
        print("1. Handshake.\n")
        print("2. Client sends: 010505050505 in AppPacket and server echos the same data back.\n")
        print("3. Client sends the two application messages: 0104040404, 03030303\n")
        print("   in a MultiAppPacket and Server echos the same two messages back in\n")
        print("   a MultiAppPacket.\n")
        print("\n")
        print("Time fields are used. Each peer sends 1 in the first message, then 2, 3, ...\n")
        print("Thus the times fields are as follows: \n")
        print("    M1: 1 (client --> server)\n")
        print("    M2: 1 (client <-- server)\n")
        print("    M3: 2 (client <-- server)\n")
        print("    M4: 2 (client --> server)\n")
        print("    AppPacket: 3 (client --> server)\n")
        print("    AppPacket: 3 (client <-- server)\n")
        print("    MultiAppPacket: 4 (client --> server)\n")
        print("    MultiAppPacket: 4 (client <-- server)\n")
        print("The lastFlag is used by Server in the last message it sends.\n")
        print("0x01 means ECHO command, and 0x03 means CLOSE command.\n")

        print("\n ---------------------------------------------------------------------\n")
        print("\nclient signature key pair:\n" + str(self.client_sig_keypair))
        print("\nclient encryption key pair:\n" + str(self.client_enc_keypair))
        print("\nserver signature key pair:\n" + str(self.server_sig_keypair))
        print("\nserver encryption key pair:\n" + str(self.server_enc_keypair))
        print("\n ----------------------- client <--> server --------------------------\n")

        await scs.handshake()

        cnt_read0 = channel.counter_read  # it's possible with MitmChannel instances only!
        cnt_write0 = channel.counter_write  # it's possible with MitmChannel instances only!

        app_request1 = bytes([0x01, 0x05, 0x05, 0x05, 0x05, 0x05])
        await scs.app_channel.write(app_request1, is_last=False)
        app_response1 = await scs.app_channel.read()

        app_request2_1 = bytes([0x01, 0x04, 0x04, 0x04, 0x04])
        app_request2_2 = bytes([0x03, 0x03, 0x03, 0x03])
        await scs.app_channel.write(app_request2_1, app_request2_2, is_last=False)
        app_response2 = await scs.app_channel.read()
        app_response3 = await scs.app_channel.read()

        cnt_read = channel.counter_read  # it's possible with MitmChannel instances only!
        cnt_write = channel.counter_write  # it's possible with MitmChannel instances only!

        # print results to stdout
        print("\n ---------------------------------------------------------------------\n")
        print("\nsession key: " + scs.session_key.hex())
        print("app_request1: " + app_request1.hex())
        print("app_response1: " + app_response1.hex())
        print("app_request2_1: " + app_request2_1.hex())
        print("app_response2: " + app_response2.hex())
        print("app_request2_2: " + app_request2_2.hex())
        print("app_response3: " + app_response3.hex())

        print("\nclient --> server handshake bytes: ", cnt_write0)
        print("client <-- server handshake bytes: ", cnt_read0)
        print("client --> server total bytes: ", cnt_write)
        print("client <-- server total bytes: ", cnt_read)

        print("\nHANDSHAKE BYTES: ", cnt_write0 + cnt_read0)
        print("TOTAL BYTES: ", cnt_write + cnt_read)
        print("\n ---------------------------------------------------------------------\n")

        if app_response1 != app_request1:
            raise AssertionError("app_response1 != app_request1")
        if app_request2_1 != app_response2:
            raise AssertionError("app_request2_1 != app_response2")
        if app_request2_2 != app_response3:
            raise AssertionError("app_request2_2 != app_response3")


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
