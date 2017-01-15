import ssl
import socket
import hashlib
import struct

class SSLConnection(object):
    def __init__(self, host, port):
        sock = socket.socket()
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        sock.connect((host, port))
        self.s = ssl.wrap_socket(sock)

    @property
    def fingerprint(self):
        cert = self.s.getpeercert(True)
        raw = hashlib.sha1(cert).digest()
        return ':'.join(['%02x' % ord(c) for c in raw])

class SSLTunnel(SSLConnection):
    def __init__(self, session_id, host, port):
        super(SSLTunnel, self).__init__(host, port)

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

        print ">>> ", " ".join(['%02x' % ord(x) for x in buf])

        self.s.write(buf)

    def read(self):
        length = self.s.read(4)
        if len(length) != 4:
            raise IOError("Short read from server")
        plen, = struct.unpack('>L', length)
        data = self.s.read(plen)
        print "<<< ", " ".join(['%02x' % ord(x) for x in data])
        if len(data) != plen:
            raise IOError("Short read from server")
        return data

    def close(self):
        self.s.close()
