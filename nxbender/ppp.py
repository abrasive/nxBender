import subprocess
import threading
import pty
import os
import logging
import sys
from . import sslconn
import ssl
import signal
import select
import socket

class PPPSession(object):
    def __init__(self, options, session_id, routecallback=None):
        self.options = options
        self.session_id = session_id
        self.routecallback = routecallback

        self.pppargs = [
                'debug', 'debug',
                'dump',
                'logfd', '2',   # we extract the remote IP thru this

                'lcp-echo-interval', '10',
                'lcp-echo-failure',  '2',

                'ktune',
                'local',
                'noipdefault',
                'noccp',    # server is buggy
                'noauth',
                'nomp',
                'usepeerdns',
        ]

    def run(self):
        master, slave = pty.openpty()
        self.pty = master

        try:
            self.pppd = subprocess.Popen(['pppd'] + self.pppargs,
                                         stdin = slave,
                                         stdout = slave,
                                         stderr = subprocess.PIPE)
        except OSError as e:
            logging.error("Unable to start pppd: %s" % e.strerror)
            sys.exit(1)

        os.close(slave)

        self.tunsock = sslconn.SSLTunnel(self.session_id, self.options, self.options.server, self.options.port)
        self.pty = master

        def sigint_twice(*args):
            logging.info('caught SIGINT again, killing pppd')
            self.pppd.send_signal(signal.SIGKILL)

        def sigint(*args):
            logging.info('caught SIGINT, signalling pppd')
            self.pppd.send_signal(signal.SIGTERM)
            signal.signal(signal.SIGINT, sigint_twice)
            os.kill(os.getpid(), signal.SIGHUP) # break out of select()

        old_sigint = signal.signal(signal.SIGINT, sigint)
        signal.signal(signal.SIGHUP, signal.SIG_IGN)
        signal.signal(signal.SIGWINCH, signal.SIG_IGN)

        try:
            while self.pppd.poll() is None:
                stop = self._pump()
                if stop:
                    break
        except ssl.SSLError as e:     # unexpected
            logging.exception(e)
        except socket.error as e:     # expected (peer disconnect)
            logging.error(e.strerror)
        finally:
            if self.pppd.poll() is not None:    # pppd caused termination
                logging.error("pppd exited with code %d" % self.pppd.poll())

                if self.pppd.poll() in [2, 3]:
                    logging.warn("Are you root? You almost certainly need to be root")
            else:
                self.pppd.send_signal(signal.SIGHUP)

            logging.info("Shutting down...")
            os.close(self.pty)
            self.pppd.wait()
            signal.signal(signal.SIGINT, old_sigint)
            self.tunsock.close()

    def _pump(self):
        r_set = [self.tunsock, self.pppd.stderr]
        w_set = []

        # If the SSL tunnel is blocked on writes, apply backpressure (stop reading from pppd)
        if self.tunsock.writes_pending:
            w_set.append(self.tunsock)
        else:
            r_set.append(self.pty)

        try:
            r, w, x = select.select(r_set, w_set, [])
        except select.error:
            return True   # interrupted

        if self.tunsock in r:
            self.tunsock.read_to(self.pty)

        if self.pty in r:
            stop = self.tunsock.write_from(self.pty)
            if stop:
                return stop

        if self.tunsock in w:
            self.tunsock.write_pump()

        if self.pppd.stderr in r:
            line = self.pppd.stderr.readline().strip().decode('utf-8', errors='replace')

            if self.options.show_ppp_log:
                print("pppd: %s" % line)

            if line.startswith("remote IP address"):
                remote_ip = line.split(' ')[-1]
                self.routecallback(remote_ip)
