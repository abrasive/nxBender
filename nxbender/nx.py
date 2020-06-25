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

    def login(self, username, password, domain):
        resp = self.session.post('https://%s/cgi-bin/userLogin' % self.host,
                                 data={
                                     'username': username,
                                     'password': password,
                                     'domain': domain,
                                     'login': 'true',
                                 },
                                 headers={
                                     'X-NE-SESSIONPROMPT': 'true',
                                 },
                                )

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

        srv_options = {}
        routes = []

        # Very dodgily avoid actually parsing the HTML
        for line in resp.iter_lines():
            line = line.strip().decode('utf-8', errors='replace')
            if line.startswith('<'):
                continue
            if line.startswith('}<'):
                continue

            # split without whitespace because servers are inconsistent
            try:
                key, value = line.split('=', 1)
            except ValueError:
                logging.warn("Unexpected line in session start message: '%s'" % line)
            # remove whitespace left from splitting
            key = key.strip()
            value = value.strip()

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

        pppd = ppp.PPPSession(self.options, auth_key, routecallback=self.post_connect)
        pppd.run()
        # remove DNS entries as they will have stopped working
        if self.options.use_resolvconf:
            self.remove_dns_resolvconf(self.device)

    def post_connect(self, gateway:str, device:str):
        """Called after the PPP channel connects and obtains an IP address to complete setup.

        param gateway The IP address of the far end of the connection.
        param device The name of the local network device, e.g. ppp0
        """
        self.device = device
        # set IP routes
        self.setup_routes(gateway)
        # if needed, set DNS servers
        if self.options.use_resolvconf:
            self.set_dns_resolvconf(device)

    def setup_routes(self, gateway):
        """Called after the PPP channel connects and obtains an IP address to create routing table
        entries.
        """
        ip = pyroute2.IPRoute()

        for route in set(self.routes):
            net = ipaddress.IPv4Network(unicode(route))
            dst = '%s/%d' % (net.network_address, net.prefixlen)
            ip.route("add", dst=dst, gateway=gateway)

        logging.info("Remote routing configured, VPN is up")

    def set_dns_resolvconf(self, device:str):
        """Called after the PPP channel connects to configure DNS using resolvconf.

        param device The name of the local network device, e.g. ppp0
        """
        resolv_conf_lines = []
        # header
        resolv_conf_lines.append(f'# Generated by nxBender for {device}')

        # nameserver lines
        for dns in ['dns1', 'dns2', 'dns3']:
            try:
                resolv_conf_lines.append(f'nameserver {self.srv_options[dns]}')
            except KeyError as err:
                # ignore these, because the number of DNS servers returned will vary
                pass

        # search lines
        # The server sends both "dnsSuffixes" and "dnsSuffix" with the same (single) value
        # As I don't know how to parse the former, use the latter for now.
        try:
            domain = self.srv_options['dnsSuffix']
            resolv_conf_lines.append(f'search {domain}')
        except KeyError as err:
                # ignore if not sent
                pass

        # pass the lot to resolvconf
        # <data> | resolvconf -a ppp0
        logging.debug("DNS settings to add:")
        for line in resolv_conf_lines:
            logging.debug(f'\t{line}')
        try:
            resolvconf = subprocess.run(['resolvconf', '-a'] + [device],
                                         text = True,
                                         input ='\n'.join(resolv_conf_lines),
                                         check = True
                                         )
        except OSError as e:
            logging.error("Unable to run resolvconf: %s" % e.strerror)
        except subprocess.CalledProcessError as err:
            logging.error(
                f'resolvconf exited with status {err.returncode}: {err.stdout} {err.stderr}')


    def remove_dns_resolvconf(self, device:str):
        """Called after the PPP channel disconnects to remove DNS settings using resolvconf.

        param device The name of the local network device, e.g. ppp0
        """
        data =""
        try:
            resolvconf = subprocess.run(['resolvconf', '-f', '-d'] + [device],
                                         text = True,
                                         input = data,
                                         check = True
                                         )
        except OSError as e:
            logging.error("Unable to run resolvconf: %s" % e.strerror)
        except subprocess.CalledProcessError as err:
            logging.error(
                f'resolvconf exited with status {err.returncode}: {err.stdout} {err.stderr}')
