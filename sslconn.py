import ssl
import socket
import hashlib
import struct
import logging
import sys

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

    def write(self, data):
        buf = struct.pack('>L', len(data)) + data

        if self.options.dump_packets:
            print ">>> ", " ".join(['%02xdump_packets:' % ord(x) for x in buf])

        self.s.write(buf)

    def read(self):
        length = self.s.read(4)
        if len(length) != 4:
            raise IOError("Short read from server")
        plen, = struct.unpack('>L', length)
        data = self.s.read(plen)

        if self.options.dump_packets:
            print "<<< ", " ".join(['%02x' % ord(x) for x in data])

        if len(data) != plen:
            raise IOError("Short read from server")
        return data

    def close(self):
        self.s.close()
