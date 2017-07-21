#!/usr/bin/env python3
"""

"""
import logging

from saltchannel.dev.client_server import MpClientServerPair
from saltchannel.dev.echo_session import EchoSession


def main():
    logging.info("MpClientServerPair with EchoSession starting...");
    cs = MpClientServerPair(EchoSession())
    cs.wait_before_alive()
    logging.info("MpClientServerPair with EchoSession is active now.");

    logging.info("Starting session of EchoSession...");
    cs.run_session()
    logging.info("Client session of EchoSession finished. (Server session may still be active)");

if __name__ == '__main__':
    main()
