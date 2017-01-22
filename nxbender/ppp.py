import subprocess
import threading
import pty
import os
import logging
import sys
import sslconn
import signal
import select

class PPPSession(object):
    def __init__(self, options, session_id, routecallback=None, defaultroute=False):
        pppargs = [
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

        master, slave = pty.openpty()
        self.pty = master

        self.options = options
        self.routecallback = routecallback

        try:
            self.pppd = subprocess.Popen(['pppd'] + pppargs,
                                         stdin = slave,
                                         stdout = slave,
                                         stderr = subprocess.PIPE)
        except OSError, e:
            logging.error("Unable to start pppd: %s" % e.strerror)
            sys.exit(1)

        os.close(slave)

        self.tunsock = sslconn.SSLTunnel(session_id, options, options.server, options.port)
        self.pty = master

        def sigint(*args):
            logging.info('caught SIGINT, signalling pppd')
            self.pppd.send_signal(signal.SIGINT)
        old_sigint = signal.signal(signal.SIGINT, sigint)

        try:
            while self.pppd.poll() is None:
                stop = self._pump()
                if stop:
                    break
        finally:
            self.pppd.terminate()
            retcode = self.pppd.wait()
            logging.info("pppd exited with code %d" % retcode)
            signal.signal(signal.SIGINT, old_sigint)
            self.tunsock.close()

    def _pump(self):
        try:
            r, w, x = select.select([self.tunsock, self.pty, self.pppd.stderr], [], [])
        except select.error:
            return True   # interrupted

        if self.tunsock in r:
            self.tunsock.read_to(self.pty)

        if self.pty in r:
            try:
                data = os.read(self.pty, 8192)
            except OSError:
                return True # EOF
            self.tunsock.write(data)

        if self.pppd.stderr in r:
            line = self.pppd.stderr.readline().strip()

            if self.options.show_ppp_log:
                print "pppd: %s" % line

            if line.startswith("remote IP address"):
                remote_ip = line.split(' ')[-1]
                self.routecallback(remote_ip)
