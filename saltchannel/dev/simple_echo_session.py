import os
import codecs
import logging
from .client_server import Session
from saltchannel.exceptions import ComException

CLIENT_SEND_LOOPS = 10

class SimpleEchoSession(Session):
    """Client session + server session routines implementing echo protocol
    defined here: https://github.com/assaabloy-ppi/pot-main/blob/master/echo-protocol/echo-server-protocol.md"""

    def server_session(self, channel):
        try:
            while True:
                msg = channel.read_sync()
                if not msg:
                    return # client closed socket
                channel.write_sync(msg)
        except ComException:
            logging.info("Server detected closed connection")

    def client_session(self, channel):
        data = os.urandom(6)
        data_str = codecs.encode(os.urandom(6), "hex")
        for i in range(CLIENT_SEND_LOOPS):
            logging.info("[CLIENT] ReqNo:{},  Sending:  {}".format(i, data_str))
            channel.write_sync(data)
            response = codecs.encode(channel.read_sync(), 'hex')
            logging.info("[CLIENT] ReqNo:{},  Received: {}".format(i, response))