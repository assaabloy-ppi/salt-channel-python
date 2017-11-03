import sys
import logging
import time

from .client_server_a import ClientServerPairA
from .simple_echo_session_a import SimpleEchoSessionA

# Log all to stdout
handler = logging.StreamHandler(sys.stdout)
handler.setFormatter(logging.Formatter("%(relativeCreated)06d - pid:%(process)s - %(message)s"))
logging.getLogger().addHandler(handler)
logging.getLogger().setLevel(logging.INFO)

CLIENT_NUM = 3


def main():

    print()
    csa = ClientServerPairA(SimpleEchoSessionA(), CLIENT_NUM)
    csa.start_server()

    t0 = time.perf_counter()
    csa.run_sessions()
    logging.info("All client session runtime: {:.6f} ms".format(1000*(time.perf_counter()-t0)))

    csa.stop_server()


if __name__ == '__main__':
    main()