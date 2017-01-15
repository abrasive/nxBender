# nxBender

a simple Python client for netExtender VPNs (SonicWALL/Dell)

Supports basic IPv4 connectivity with routing and DNS.

## Requirements

Install Python dependencies with:

```
    pip install -r requirements.txt
```

You will also need `pppd`.

## Usage

Very simply:

```
    sudo ./nxBender --server my-sslvpn-host.com -u username -p password -d domainname
```

You can supply the server's SSL certificate fingerprint with `--fingerprint` if
you're using self-signed certificates or if you want pinning.

Options can also be placed into a configuration file - defaulting to
`/etc/nxbender` or `~/.nxbender` - such as:

```
    server = my-sslvpn-host.com
    username = username
    password = password
    fingerprint = 9d:6a:fe:04:78:93:b0:a5:38:a0:04:ac:d2:10:cb:f7:9c:42:cf:74
```

## Portability

At present the VPN routes are set up using `pyroute2`, which uses Linux's
netlink interface to manage routing. A cross-platform approach could use `ip`
and `route` binaries instead.

The output of `pppd` is parsed to determine the remote gateway address rather
than using the `ip-up` mechanism, to avoid headaches caused by differences in
implementation between distributions (somewhere Dell's client trips up). This
might prove fragile, but `pppd` is very stable nowadays.

## Why?

The official client is a pain to use; it only works out of the box on some
very specific Linux flavours, has little useful debugging output, and I had to
disassemble the binaries to even get it working on Gentoo.

The CLI component also has a number of painful behaviours, including requiring
user input to acknowledge self-signed certificates - even when reconnecting
during a session - and with no way to store the fingerprint for some reason;
so acceptance can be automated with `expect` but is then vulnerable to MitM.
It frequently leaves entries in `resolv.conf` when the VPN is down, breaking
DNS for the entire system.

When I took a peek the protocol was trivial so I spent a couple of hours on a
Sunday smashing out a replacement. Thus far it has proven quite reliable.

## TODO

Not currently implemented are:

- IPv6
- DNS search suffixes
- auto reconnection
- configurable timeouts/link loss detection
