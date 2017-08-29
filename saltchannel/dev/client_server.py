import sys
import sys
import time
import random
import socket
import logging
import threading
import socketserver
from abc import ABCMeta, abstractmethod
import codecs

from saltchannel.channel import SocketChannel, StreamChannel
from saltchannel.channel_a import AsyncizedChannel
from .mitm_channel import MitmChannel
from .mitm_channel_a import AsyncizedMitmChannel

class Session(metaclass=ABCMeta):
    """Client session + server session routines"""

    @abstractmethod
    def server_session(self, channel):
        pass

    @abstractmethod
    def client_session(self, channel):
        pass


class ClientServerPair:
    def __init__(self, session):
        self.session = session
        self.is_alive = False
        self.is_session_active = False

    def wait_before_alive(self):
        self.is_alive = True

    def run_session(self):
        self.is_session_active = True


class ThreadedClientServerPair(ClientServerPair):
    """Client + server pair implemented using 'threading' library
    Each part runs in own thread and communicate using ByteChannel specified.
    Note: class user MUST submit appropriate ByteChannel instance"""
    pass


class MpClientServerPair(ClientServerPair):
    """Client + server pair implemented using 'multiprocessing' library
    Each part runs in own process and communicate using ByteChannel specified.
    Note: class user MUST submit appropriate ByteChannel instance e.g. SocketChannel or PipeChannel"""

    @staticmethod
    def _server_handler_factory(session):
        class TCPRequestHandler(socketserver.BaseRequestHandler):

            def handle(self):
                #ch = AsyncizedChannel(SocketChannel(self.request))
                ch = SocketChannel(self.request)

                session.server_session(ch)
                #session.server_session(MitmChannel(ch, log=logging.getLogger(__name__)))
                # Echo the back to the client
              #  try:
              #      while True:
              #          data = self.request.recv(4096)
              #          if not data:
              #              return
              #          print("len:{}, data:'{}'".format(len(data), codecs.encode(data, 'hex')))
              #          self.request.send(data)
               # except ConnectionResetError:
               #     return

        return TCPRequestHandler

    class TestTCPServer(socketserver.TCPServer):
        pass


    def __init__(self, session):
        super(MpClientServerPair, self).__init__(session)
        #self.chaSocketChannel(sock)


    def start_server(self):
        self.server = MpClientServerPair.TestTCPServer(("localhost", 0), self._server_handler_factory(self.session))
        server_thread = threading.Thread(target=self.server.serve_forever)
        # Exit the server thread when the main thread terminates
        server_thread.daemon = True
        server_thread.start()
        self.is_alive = True

    def run_sessions(self, num, jitter=True):
        thread_list = []
        for i in range(1, num+1):
            client_thread = threading.Thread(target=self._run_session)
            thread_list.append(client_thread)
            if jitter:
                time.sleep(0.0001*random.randint(1, 999))
            client_thread.start()

        # wait for all session threads to finish
        for x in thread_list:
            x.join()

    def _run_session(self):
        # server session de-facto started with MpClientServerPair.TCPRequestHandler

        # now create ByteChannel
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.connect(self.server.server_address)
            channel = SocketChannel(sock)

            self.is_session_active = True

            # invoke method(-s) in Session object instance
            #self.session.client_session(channel)

            #self.session.client_session(AsyncizedMitmChannel(channel, log=logging.getLogger(__name__)))
            self.session.client_session(MitmChannel(channel, log=logging.getLogger(__name__)))

            # self.session.client_session(MitmChannel(channel, log=logging.getLogger(__name__)))


        except Exception as e:
            logging.exception(e)
        finally:
            sock.close()

        self.is_session_active = False

    def stop_server(self):
        logging.info("Shutting down server...")
        self.server.shutdown()
        self.server.server_close()
        logging.info("Server stopped.")
