import ssl
import socket
import hashlib
import struct
import logging
import sys
import os

class SSLConnection(object):
    def __init__(self, options, host, port):
        self.options = options

        sock = socket.socket()
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.connect((host, port))

        self.s = ssl.wrap_socket(sock)

        if getattr(options, 'fingerprint', False):
            if self.fingerprint != options.fingerprint.lower():
                logging.error("Certificate fingerprint verification failed; server's fingerprint is %s" % self.fingerprint)
                sys.exit(1)

    @property
    def fingerprint(self):
        cert = self.s.getpeercert(True)
        raw = hashlib.sha1(cert).digest()
        return ':'.join(['%02x' % ord(c) for c in raw])

def print_fingerprint(host):
    conn = SSLConnection(None, host, 443)
    print "Server's certificate fingerprint: %s" % conn.fingerprint

class SSLTunnel(SSLConnection):
    def __init__(self, session_id, *args, **kwargs):
        super(SSLTunnel, self).__init__(*args, **kwargs)

        headers={
            'X-SSLVPN-PROTOCOL': '2.0',
            'X-SSLVPN-SERVICE': 'NETEXTENDER',
            'Proxy-Authorization': session_id,
            'X-NX-Client-Platform': 'Linux',
            'Connection-Medium': 'MacOS',
            'X-NE-PROTOCOL': '2.0',
        }

        self.s.write('CONNECT localhost:0  HTTP/1.0\r\n')
        for hdr in headers.iteritems():
            self.s.write('%s: %s\r\n' % hdr)

        self.s.write('\r\n')

        self.s.setblocking(0)

        self.buf = ''
        self.wbuf = ''

    def fileno(self):
        return self.s.fileno()

    def read_to(self, target_fd):
        while True:
            try:
                data = self.s.recv(8192)
                self._handle_data(data, target_fd)
            except ssl.SSLWantReadError:
                return

    def write_from(self, src_fd):
        try:
            data = os.read(src_fd, 8192)
        except OSError:
            return True # EOF from pppd

        self.write(data)

    def _handle_data(self, data, target):
        self.buf += data

        while len(self.buf) > 4:
            plen, = struct.unpack('>L', self.buf[:4])
            if len(self.buf) < 4 + plen:
                return

            os.write(target, self.buf[4:4+plen])
            self.buf = self.buf[4+plen:]

    def write(self, data):
        self.wbuf += data
        self.write_pump()

    @property
    def writes_pending(self):
        return len(self.wbuf) > 0

    def write_pump(self):
        while len(self.wbuf):
            packet = self.wbuf[:1514]
            buf = struct.pack('>L', len(packet)) + packet
            n = self.s.send(buf)
            if n == len(buf):
                self.wbuf = self.wbuf[len(packet):]
            else:
                return

    def close(self):
        self.s.close()
