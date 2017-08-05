#!/usr/bin/env python2
import requests
import logging
import ppp
import pyroute2
import ipaddress
import atexit

from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager

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
                'User-Agent': 'SonicWALL NetExtender for Linux 8.6.800',
                'X-NE-pda': 'true',
        }

        logging.info("Logging in...")
        self.login(
                self.options.username,
                self.options.password,
                self.options.domain
            )

        logging.info("Starting session...")
        self.start_session()

        logging.info("Logging out ...")
        self.session.cookies = requests.cookies.cookiejar_from_dict(self.loginCookie)
        self.logout()

        logging.info("Dialing up tunnel...")
        self.tunnel()

    def login(self, username, password, domain):
        resp = self.session.post('https://%s/cgi-bin/userLogin' % self.host,
                                data={
                                    "username": username,
                                    "password": password,
                                    "domain": domain,
                                    "login": "true"
                                 },
                                 headers={
                                     'X-NE-SESSIONPROMPT': 'true',
                                 },
                                )
        self.loginCookie = requests.utils.dict_from_cookiejar(self.session.cookies)
        error = resp.headers.get('X-NE-Message', None)
        error = resp.headers.get('X-NE-message', error)
        if error:
            raise IOError('Server returned error: %s' % error)

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

        self.cookie = requests.utils.dict_from_cookiejar(self.session.cookies)
        srv_options = {}
        routes = []

        # Very dodgily avoid actually parsing the HTML
        for line in resp.iter_lines():
            line = line.strip()
            if line.startswith('<'):
                continue
            if line.startswith('}'):
                continue

            try:
                key, value = line.split(' =', 1)
                key = key.strip()
                value = value.strip()
                if value[-1:] == ';' :
                    value = value[:-1]

                if key == 'Route':
                    routes.append(value)
                elif key not in srv_options:
                    srv_options[key] = value
                else:
                    logging.info('Duplicated srv_options value %s = %s' % (key, value))
            except:
                logging.info("Unparsed line ...")

        self.srv_options = srv_options
        self.routes = routes

    def tunnel(self):
        """
        Begin PPP tunneling.
        """

        pppd = ppp.PPPSession(self.options, self.cookie['swap'], routecallback=self.setup_routes)
        pppd.run()

    def setup_routes(self, gateway):
        ip = pyroute2.IPRoute()

        for route in self.routes:
            net = ipaddress.IPv4Network(unicode(route))
            dst = '%s/%d' % (net.network_address, net.prefixlen)
            ip.route("add", dst=dst, gateway=gateway)

        logging.info("Remote routing configured, VPN is up")
