"""Example session data; Example session data, does A1-A2
This is blocking socket example"""

import os
import sys
import logging
import timeit
import functools

from saltchannel import util
from saltchannel.a1a2.packets import A1Packet, A2Packet
from saltchannel.a1a2.a1_client_session import A1ClientSession

from saltchannel.v2.salt_server_session import SaltServerSession
from saltchannel.util.crypto_test_data import CryptoTestData
from saltchannel.dev.client_server import MpClientServerPair
from .client_server import Session
from saltchannel.exceptions  import ComException

# Log all to stdout
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("%(relativeCreated)06d - pid:%(process)s - %(message)s"))
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(logging.INFO)

SESSION_NUM = 1


class ExampleSession(Session):

    def __init__(self):
        self.server_sig_keypair = CryptoTestData.bSig
        self.server_enc_keypair = CryptoTestData.bEnc

    def server_session(self, channel):
        """Server-side session implementation for A1-A2"""
        try:
            while True:
                sss = SaltServerSession(self.server_sig_keypair, channel)

                sss.a2 = A2Packet(case=A2Packet.Case.A2_DEFAUT)
                sss.a2.Prot[0].P1 = util.cbytes(A2Packet.SC2_PROT_STRING)
                sss.a2.Prot[0].P2 = util.cbytes(b'ECHO------')

                sss.enc_keypair = self.server_enc_keypair
                sss.handshake_sync()

                logging.info("A2 packet just sent. Server decides to close current connection.")
                logging.info("SRV closing connection")
                return

        except ComException:
            logging.info("ComException: Server detected closed connection")

    def client_session(self, channel):
        """Client-side session implementation for basic handshake"""

        cs = A1ClientSession(channel)
        cs.a1.data.AddressType = A1Packet.ADDRESS_TYPE_PUBKEY
        cs.a1.data.AddressSize = 32
        cs.a1.Address = b'\x08' * 32  # pubkey is filled with 0x08

        print("\n ----------------------- client <--> server --------------------------\n")
        cs.do_a1a2_sync()

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


def main():

    print()
    logging.info(os.path.basename(__file__) + " starting...")
    cs = MpClientServerPair(ExampleSession())
    cs.start_server()

    print()
    ses_time = (1000/SESSION_NUM) * timeit.Timer(functools.partial(cs.run_sessions, SESSION_NUM)).timeit(1)

    print()
    logging.info("Session finished.")
    logging.info("Average client session runtime: {:.6f} ms".format(ses_time))
    cs.stop_server()


if __name__ == '__main__':
    main()