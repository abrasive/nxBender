import subprocess
import threading
import pty
import os
import logging
import sys
import sslconn

class PPPSession(object):
    def __init__(self, options, session_id, routecallback=None, defaultroute=False):
        pppargs = [
                'debug',
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

        self.sock = sslconn.SSLTunnel(session_id, options, options.server, 443)

        self.stopping = False
        self.stop_reason = None

        self.p2s_thread = threading.Thread(target=self.ppp2sock)
        self.p2s_thread.start()
        self.s2p_thread = threading.Thread(target=self.sock2ppp)
        self.s2p_thread.start()
        self.stderr_thread = threading.Thread(target=self.handle_stderr)
        self.stderr_thread.start()

    def wait(self):
        try:
            code = self.pppd.wait()
            stop_reason = 'pppd exited with code %d' % code
        except KeyboardInterrupt:
            stop_reason = 'SIGINT received'

        self.stop(stop_reason)

    def stop(self, stop_reason):
        if self.stop_reason is None:
            self.stop_reason = stop_reason
            logging.info('Exiting: %s' % stop_reason)

        self.stopping = True
        try:
            self.pppd.terminate()
        except OSError: # it's already dead
            pass

        self.p2s_thread.join()
        self.s2p_thread.join()
        self.stderr_thread.join()

    def ppp2sock(self):
        while not self.stopping:
            try:
                self.sock.write(os.read(self.pty, 65536))
            except IOError:
                self.stop('SSL write failed')
            except OSError:
                # pppd closed the pipe; this is caught by wait() above
                return

    def sock2ppp(self):
        while not self.stopping:
            try:
                os.write(self.pty, self.sock.read())
            except IOError:
                self.stop('SSL read failed')
            except OSError:
                # pppd closed the pipe; this is caught by wait() above
                return

    def handle_stderr(self):
        """Read and handle pppd's output on stderr.

        The primary purpose of this is to detect the remote endpoint
        address so that we can set up routing. This replaces the classic
        mechanism using /etc/ip-up; the reason being that the ip-up
        system is different on different distributions and so it's a
        little messy to work with, and this keeps all the mess in one box
        instead.
        """
        while not self.stopping:
            try:
                line = self.pppd.stderr.readline().strip()
            except IOError:
                return

            if self.options.show_ppp_log:
                print "pppd: %s" % line

            if line.startswith("remote IP address"):
                remote_ip = line.split(' ')[-1]
                self.routecallback(remote_ip)
