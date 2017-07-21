
from abc import ABCMeta, abstractmethod


class Session(metaclass=ABCMeta):
    """Client session + server session routines"""

    @abstractmethod
    def server_session(self):
        pass

    @abstractmethod
    def client_session(self):
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
    raise NotImplementedError("ThreadedClientServerPair is not implemented")


class MpClientServerPair(ClientServerPair):
    """Client + server pair implemented using 'multiprocessing' library
    Each part runs in own process and communicate using ByteChannel specified.
    Note: class user MUST submit appropriate ByteChannel instance e.g. SocketChannel or PipeChannel"""

    def __init__(self, session):
        super(MpClientServerPair, self).__init__(session)

