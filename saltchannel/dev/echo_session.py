from .client_server import Session


class EchoSession(Session):
    """Client session + server session routines implementing echo protocol
    defined here: https://github.com/assaabloy-ppi/pot-main/blob/master/echo-protocol/echo-server-protocol.md"""


    def server_session(self):
        pass

    def client_session(self):
        pass
