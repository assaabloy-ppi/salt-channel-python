"""Example session data; used as an appendix to theSalt Channel v2 specification.
An executable class that outputs data needed to reproduce a simple Salt Channel session."""

import os
import sys
import logging
import timeit
import codecs
import functools

from saltchannel.v2.salt_client_session import SaltClientSession
#from saltchannel.v2.salt_server_session import SaltServerSession
from .tunnel import Tunnel
from saltchannel.util.crypto_test_data import CryptoTestData


# Log all to stdout
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("%(relativeCreated)06d - pid:%(process)s - %(message)s"))
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(logging.INFO)

from saltchannel.dev.client_server import MpClientServerPair
from saltchannel.dev.simple_echo_session import SimpleEchoSession
from .client_server import Session
from saltchannel.exceptions  import ComException

SESSION_NUM = 1


class ExampleSession(Session):
    """Expected to implement same protocol as:
    https://github.com/assaabloy-ppi/salt-channel/blob/master/src/saltchannel/dev/ExampleSessionData.java"""

    def server_session(self, channel):
        try:
            while True:
                msg = channel.read()
                if not msg:
                    return # client closed socket
                channel.write(msg)
        except ComException:
            logging.info("Server detected closed connection")

    def client_session(self, channel):
        data = os.urandom(6)
        data_str = codecs.encode(os.urandom(6), "hex")
        for i in range(1):
            logging.info("[CLIENT] ReqNo:{},  Sending:  {}".format(i, data_str))
            channel.write(data)
            response = codecs.encode(channel.read(), 'hex')
            logging.info("[CLIENT] ReqNo:{},  Received: {}".format(i, response))


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