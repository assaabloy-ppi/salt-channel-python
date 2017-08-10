"""Example session data; used as an appendix to theSalt Channel v2 specification.
An executable class that outputs data needed to reproduce a simple Salt Channel session."""
import os
import sys
import logging
import timeit
import functools

from saltchannel.v2.salt_client_session import SaltClientSession
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
    """Expected to implement same protocol as:
    https://github.com/assaabloy-ppi/salt-channel/blob/master/src/saltchannel/dev/ExampleSessionData.java"""

    def __init__(self):
        self.server_sig_keypair = CryptoTestData.bSig
        self.server_enc_keypair = CryptoTestData.bEnc
        self.client_sig_keypair = CryptoTestData.aSig
        self.client_enc_keypair = CryptoTestData.aEnc

    def server_session(self, channel):
        """Server-side session implementation for basic handshake"""
        try:
            while True:
                #msg = channel.read()
                sss = SaltServerSession(self.server_sig_keypair, channel)
                sss.enc_keypair = self.server_enc_keypair
                sss.buffer_m2 = True
                sss.handshake()
                sss.app_channel.write(sss.app_channel.read())  # echo once at app layer

                #if not msg:
                #    return # client closed socket
        except ComException:
            logging.info("Server detected closed connection")

    def client_session(self, channel):
        """Client-side session implementation for basic handshake"""
        scs = SaltClientSession(self.client_sig_keypair, channel)
        scs.enc_keypair = self.client_enc_keypair
        scs.buffer_M4 = True

        # print session initial details to stdout
        print("======== example_session_data.py ========")
        print("\nclient signature key pair:\n" + str(self.client_sig_keypair))
        print("\nclient encryption key pair:\n" + str(self.client_enc_keypair))
        print("\nserver signature key pair:\n" + str(self.server_sig_keypair))
        print("\nserver encryption key pair:\n" + str(self.server_enc_keypair))
        print("\n ----------------------- client <--> server --------------------------\n")

        scs.handshake()

        cnt_read0 = channel.counter_read  # it's possible with MitmChannel instances only!
        cnt_write0 = channel.counter_write  # it's possible with MitmChannel instances only!

        app_request = bytes([0x01, 0x05, 0x05, 0x05, 0x05, 0x05])
        scs.app_channel.write(app_request)
        app_response = scs.app_channel.read()

        cnt_read = channel.counter_read  # it's possible with MitmChannel instances only!
        cnt_write = channel.counter_write  # it's possible with MitmChannel instances only!

        # print results to stdout
        print("\n ---------------------------------------------------------------------\n")
        print("\nsession key: " + scs.session_key.hex())
        print("app request: " + app_request.hex())
        print("app response: " + app_response.hex())

        print("\nclient --> server handshake bytes: ", cnt_write0)
        print("client <-- server handshake bytes: ", cnt_read0)
        print("client --> server total bytes: ", cnt_write)
        print("client <-- server total bytes: ", cnt_read)

        print("\nHANDSHAKE BYTES: ", cnt_write0 + cnt_read0)
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