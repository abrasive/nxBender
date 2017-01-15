import subprocess
import threading
import pty
import os
import logging
import sys

class PPPSession(object):
    def __init__(self, options, tunnelsock, defaultroute=False):
        pppargs = [
                'debug',

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

        if options.show_ppp_log:
            pppargs.extend(['logfd', '2'])

        master, slave = pty.openpty()
        self.pty = master

        try:
            self.pppd = subprocess.Popen(['pppd'] + pppargs,
                                         stdin = slave,
                                         stdout = slave)
        except OSError, e:
            logging.error("Unable to start pppd: %s" % e.strerror)
            sys.exit(1)

        os.close(slave)

        self.sock = tunnelsock

        self.stopping = False
        self.stop_reason = None

        self.p2s_thread = threading.Thread(target=self.ppp2sock)
        self.p2s_thread.start()
        self.s2p_thread = threading.Thread(target=self.sock2ppp)
        self.s2p_thread.start()

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
