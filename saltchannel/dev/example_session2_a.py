"""Example session data; Example session data, does A1-A2
This is asyncio-based version of 'example_session2.py' """

import sys
import logging
import time

from saltchannel import util
from saltchannel.a1a2.packets import A1Packet, A2Packet
from .client_server_a import ClientServerPairA
from .mitm_channel import MitmChannel

from .client_server_a import SessionA
from saltchannel.channel  import AsyncioChannel

from saltchannel.v2.salt_server_session import SaltServerSession
from saltchannel.util.crypto_test_data import CryptoTestData
from saltchannel.a1a2.a1_client_session import A1ClientSession

# Log all to stdout
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("%(relativeCreated)06d - pid:%(process)s - %(message)s"))
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(logging.INFO)

CLIENT_NUM = 1


class ExampleSessionA(SessionA):

    def __init__(self):
        self.server_sig_keypair = CryptoTestData.bSig
        self.server_enc_keypair = CryptoTestData.bEnc

    async def server_session(self, reader, writer):
        """Server-side session implementation for A1-A2 protocol"""
        addr = writer.get_extra_info('peername')
        logging.info("SRV accepted connection from: {:s}".format(str(addr)))

        channel = AsyncioChannel(reader, writer)

        sss = SaltServerSession(self.server_sig_keypair, channel)

        sss.a2 = A2Packet(case=A2Packet.Case.A2_DEFAUT)
        sss.a2.Prot[0].P1 = util.cbytes(A2Packet.SC2_PROT_STRING)
        sss.a2.Prot[0].P2 = util.cbytes(b'ECHO------')

        sss.enc_keypair = self.server_enc_keypair
        await sss.handshake()

        logging.info("A2 packet just sent. Server decides to close current connection.")
        logging.info("SRV closing connection")
        channel.close()

    async def client_session(self, reader, writer):
        """Client-side session implementation for A1-A2"""
        ch = AsyncioChannel(reader, writer)
        channel = MitmChannel(ch, log=logging.getLogger(__name__))  # maybe better to move this to client_server_a.py

        cs = A1ClientSession(channel)
        cs.a1.data.AddressType = A1Packet.ADDRESS_TYPE_PUBKEY
        cs.a1.data.AddressSize = 32
        cs.a1.Address = b'\x08' * 32  # pubkey is filled with 0x08

        print("\n ----------------------- client <--> server --------------------------\n")
        await cs.do_a1a2()

        # print session initial details to stdout
        print("\n======== example_session2.py ========")
        print("\nExample session data for Salt Channel v2.")
        print("An A1-A2 session; one 'prot' with P1='{}' and P2='{}'."
              .format(bytes(cs.a2.Prot[0].P1), bytes(cs.a2.Prot[0].P2)))
        print("The *pubkey* type of address (AddressType 1) is used in A1.")
        print("As a simple example, the public key consists of 32 bytes, all set to 0x08.")

        cnt_read = channel.counter_read  # it's possible with MitmChannel instances only!
        cnt_write = channel.counter_write  # it's possible with MitmChannel instances only!

        # print results to stdout
        print("\n ---------------------------------------------------------------------\n")
        print("client --> server total bytes: ", cnt_write)
        print("client <-- server total bytes: ", cnt_read)
        print("TOTAL BYTES: ", cnt_write + cnt_read)
        print("\n ---------------------------------------------------------------------\n")

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
