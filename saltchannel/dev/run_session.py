import sys
import logging
import timeit
import functools

# Log all to stdout
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("%(relativeCreated)06d - pid:%(process)s - %(message)s"))
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(logging.INFO)

from saltchannel.dev.client_server import MpClientServerPair
from saltchannel.dev.simple_echo_session import SimpleEchoSession


def main():

    print()
    logging.info("MpClientServerPair with SimpleEchoSession starting...")
    cs = MpClientServerPair(SimpleEchoSession())
    cs.start_server()
    logging.info("MpClientServerPair with SimpleEchoSession is active now.")
    logging.info("Starting session [SimpleEchoSession]...")

    sessions = 10
    ses_time = (1000/sessions) * timeit.Timer(functools.partial(cs.run_sessions, sessions)).timeit(1)
    logging.info("Average client session runtime: {:.6f} ms".format(ses_time))

    logging.info("Session finished.")
    logging.info("Client session of SimpleEchoSession finished. (Server session may still be active)")

    cs.stop_server()

if __name__ == '__main__':
    main()
