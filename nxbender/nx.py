#!/usr/bin/env python2
import requests
import logging
from . import ppp
import pyroute2
import ipaddress
import atexit
import subprocess

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager

try:
    unicode
except NameError:
    unicode = str

def prompt_for_response(options, prompt_string):
    pinentry = options.pinentry
    if not pinentry:
        pinentry = 'pinentry'

    try:
        proc = subprocess.Popen([pinentry],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                encoding='utf-8',
                bufsize=0,
                )
    except FileNotFoundError:
        if options.pinentry and options.pinentry != 'none':
            # if we were explicitly told to use pinentry, this is an error
            raise
        else:
            # fall back to terminal prompt
            return input(prompt_string + ' ')

    def expect(prefix):
        line = proc.stdout.readline().strip('\n')
        if not line.startswith(prefix):
            raise ValueError('Unexpected response from pinentry: "%s"' % line)
        return line[len(prefix)+1:]

    expect('OK')

    proc.stdin.write('SETTITLE nxBender\n')
    expect('OK')

    proc.stdin.write('SETDESC %s\n' % prompt_string.strip())
    expect('OK')

    proc.stdin.write('SETPROMPT Response:\n')
    expect('OK')

    proc.stdin.write('GETPIN\n')
    response = expect('D')
    expect('OK')

    proc.stdin.close()
    proc.wait()
    return response

class FingerprintAdapter(HTTPAdapter):
    """"Transport adapter" that allows us to pin a fingerprint for the `requests` library."""
    def __init__(self, fingerprint):
        self.fingerprint = fingerprint
        super(FingerprintAdapter, self).__init__()

    def init_poolmanager(self, connections, maxsize, block=False):
        self.poolmanager = PoolManager(
            num_pools=connections, maxsize=maxsize,
            block=block, assert_fingerprint=self.fingerprint)

class NXSession(object):
    def __init__(self, options):
        self.options = options

    def run(self):
        self.host = self.options.server + ':%d' % self.options.port
        self.session = requests.Session()

        if self.options.fingerprint:
            self.session.verify = False
            self.session.mount('https://', FingerprintAdapter(self.options.fingerprint))

        self.session.headers = {
                'User-Agent': 'Dell SonicWALL NetExtender for Linux 8.1.789',
        }

        logging.info("Logging in...")
        self.login(
                self.options.username,
                self.options.password,
                self.options.domain
            )

        logging.info("Starting session...")
        self.start_session()

        logging.info("Dialing up tunnel...")
        self.tunnel()

    def login(self, username, password, domain, extra_data={}):
        data = {
                'username': username,
                'password': password,
                'domain': domain,
                'login': 'true',
                }
        data.update(extra_data)

        resp = self.session.post('https://%s/cgi-bin/userLogin' % self.host,
                                 data=data,
                                 headers={
                                     'X-NE-SESSIONPROMPT': 'true',
                                 },
                                )

        message = resp.headers.get('X-NE-Message', None)
        message = resp.headers.get('X-NE-message', message)

        two_factor = resp.headers.get('X-NE-tf', None)
        if two_factor == '5':
            logging.info('2FA required, prompting for response')
            response = prompt_for_response(self.options, message)
            return self.login(username, password, domain, extra_data={
                'pstate': resp.headers.get('X-NE-rsastate'),
                'state': 'RADIUSCHALLENGE',
                'radiusReply': response,
                })

        if two_factor is not None:
            raise IOError("Server requested two-factor auth method '%s', which we don't understand" % two_factor)

        if message:
            raise IOError('Server returned error: %s' % message)

        atexit.register(self.logout)

    def logout(self):
        # We need to try, but if we went down because we can't talk to the server? - not a big deal.
        try:
            self.session.get('https://%s/cgi-bin/userLogout' % self.host)
        except:
            pass

    def start_session(self):
        """
        Start a VPN session with the server.

        Must be logged in.
        Stores srv_options and routes returned from the server.
        """

        resp = self.session.get('https://%s/cgi-bin/sslvpnclient' % self.host,
                                params={
                                    'launchplatform': 'mac',
                                    'neProto': 3,
                                    'supportipv6': 'no',
                                },
                               )
        error = resp.headers.get('X-NE-Message', None)
        error = resp.headers.get('X-NE-message', error)
        if error:
            raise IOError('Server returned error: %s' % error)

        srv_options = {}
        routes = []

        # Very dodgily avoid actually parsing the HTML
        for line in resp.iter_lines():
            line = line.strip().decode('utf-8', errors='replace')
            if line.startswith('<'):
                continue
            if line.startswith('}<'):
                continue

            try:
                key, value = line.split(' = ', 1)
            except ValueError:
                logging.warn("Unexpected line in session start message: '%s'" % line)

            if key == 'Route':
                routes.append(value)
            elif key not in srv_options:
                srv_options[key] = value
            else:
                logging.info('Duplicated srv_options value %s = %s' % (key, value))

            logging.debug("srv_option '%s' = '%s'" % (key, value))

        self.srv_options = srv_options
        self.routes = routes

    def tunnel(self):
        """
        Begin PPP tunneling.
        """

        tunnel_version = self.srv_options.get('NX_TUNNEL_PROTO_VER', None)

        if tunnel_version is None:
            auth_key = self.session.cookies['swap']
        elif tunnel_version == '2.0':
            auth_key = self.srv_options['SessionId']
        else:
            logging.warn("Unknown tunnel version '%s'" % tunnel_version)
            auth_key = self.srv_options['SessionId']    # a guess

        pppd = ppp.PPPSession(self.options, auth_key, routecallback=self.setup_routes)
        pppd.run()

    def setup_routes(self, gateway):
        ip = pyroute2.IPRoute()

        for route in set(self.routes):
            net = ipaddress.IPv4Network(unicode(route))
            dst = '%s/%d' % (net.network_address, net.prefixlen)
            ip.route("add", dst=dst, gateway=gateway)

        logging.info("Remote routing configured, VPN is up")
