# ivansible.srv_dyndns

[![Github Test Status](https://github.com/ivansible/srv-dyndns/workflows/Molecule%20test/badge.svg?branch=master)](https://github.com/ivansible/srv-dyndns/actions)
[![Travis Test Status](https://travis-ci.org/ivansible/srv-dyndns.svg?branch=master)](https://travis-ci.org/ivansible/srv-dyndns)
[![Ansible Galaxy](https://img.shields.io/badge/galaxy-ivansible.srv__dyndns-68a.svg?style=flat)](https://galaxy.ansible.com/ivansible/srv_dyndns/)

This role will setup dynamic DNS service on linux with a few features/limitations:
- it can update DNS zone in CloudFlare;
- it can take client IP address from the optional `myip` query argument
  or from the client source address (probably using the `X-Real-IP` nginx header);
- the web service will work behind nginx and depend on it to provide TLS security;
- besides handling web requests, the service can periodically access client's
  device, detect external IPv4/IPv6 address and delegated internal IPv6 prefix
  and update IPv6 addresses of configured internal hosts in DNS.

Since some routers (eg Keenetic) can only send IPv4, the service can use a special
trick to detect the router's external IPv6 address - connect to `icanhazip.com`
via internal proxy server installed on the router.
Note that proxy (eg. `srelay` socks proxy on OpenWRT/Entware) should be banned
for outside clients.

Besides external addresses a router can have a delegated IPv6 prefix.
This service can detect this prefix and update a few preconfigured hosts in DNS.
The detection supports only Keenetic CLI and OpenWRT.


## Requirements

None


## Variables

Available variables are listed below, along with default values.

    srv_dyndns_enable: true
This flag should be set to `true` only on those inventory host(s)
where dynamic DNS is going to be installed.

    srv_dyndns_cloudflare_email: ~
    srv_dyndns_cloudflare_token: ~
Credentials for CloudFlare.

    srv_dyndns_domain: example.com
All dynamic hosts will be added in this domain.
The zone for this domain should be already added in CloudFlare.

    srv_dyndns_internal_port: 35353
    srv_dyndns_web_path: /dyndns
    srv_dyndns_web_user: dyndns
    srv_dyndns_web_pass: supersecret
Parameters for DynDNS web server.
Web requests should have `hostname` query argument beloging to the above domain,
otherwise web server will reject such requests.
The `myip` query argument is optional and defaults to the client's IP address.
The web port will not be open in firewall.
Rather, nginx will be configured to redirect given path to this port.

    srv_dyndns_poll_enable: false
    srv_dyndns_poll_interval: 3600
In addition to web request handling the service can periodically refresh
external IPv4/IPv6 device addresses using socks method and device's IPv6 prefix
using internal SSH login. Turn this off if you don't have access to internal
device services.

    srv_dyndns_main_host: myhost
If host name from web request is equal to the main host, the service will
remotely run `curl` via ssh on the host to probe for real IPv4/IPv6 address
using the `icanhazip.com` web service.

    srv_dyndns_ssh_url: ssh://root[:password]@127.0.0.1:2222[?keyfile=~/.ssh/private.key]
Non-empty setting activates IPv6 prefix probing via SSH login into router.
It will connect to OpenWRT/Entware firware of Keenetic using SSH
by using either optional password or private key from the URL query,
then send OpenWRT command `/opt/sbin/ip -o -6 route show`.
Listed prefixes can be further narrowed by length/interface filters.
The first available (or passed by filters) prefix is used to update
IPv6 addresses of prefix hosts.

    srv_dyndns_main_cmd: ~
If `main_cmd` is not empty, the service will perform ssh login
into `ssh_url` upon address changes and invoke this command.

    srv_dyndns_node_cmd: ~
    srv_dyndns_node_hosts: ~
The `node_hosts` is an optional list of ssh URLs like the main `ssh_url`
and `node_cmd` is similar to `main_cmd`, but will be invoked on the given
list of hosts.

    srv_dyndns_service_user: ~
If user is defined, dyndns service will run as this unix user.
By default, service runs as user `nobody`.

    srv_dyndns_ssh_keyfile: ~
If `keyfile` is defined, the given ssh key will be installed in
the `.ssh` subdirectory of the service user's home directory and
the `keyfile=...` clause will be added in the ssh url.

    srv_dyndns_prefix_len: 0|64|56
By default (or when this setting is zero) the first available IPv6 prefix is used.
This setting allows to limit prefixes to those with given prefix length.

    srv_dyndns_prefix_interface: ISP|br0
This setting (when non-empty) allows to limit prefixes to those with given interface.
Note that CLI and OpenWRT firware use different interface names.

    srv_dyndns_prefix_hosts:
      host1: 2001:db8::1
      host2: 2001:db8::2
This is a dictionary where keys give unqualified host names in the configured domain.
Values are concatenated with IPv6 prefix and the resulting IPv6 addresses are
registered in DNS.

    srv_dyndns_verbose: 2
Verbosity level:
0 = no logging, 1 = only errors, 2 = normal messages, 3 = debugging, 4 = debug api calls.


## Tags

- `srv_dyndns_install` -- install required system packages
- `srv_dyndns_script` -- install dyndns server executable
- `srv_dyndns_config` -- create configuration files for dyndns
- `srv_dyndns_service` -- setup systemd service for dyndns
- `srv_dyndns_keyfile` -- install key file for ssh login
- `srv_dyndns_nginx` -- setup nginx fronting
- `srv_dyndns_all` -- all of the above


## Dependencies

- `ivansible.srv_cdn`


## Example Playbook

    - hosts: myserver
      roles:
         - role: ivansible.srv_dyndns
           srv_dyndns_enable: true
           srv_dyndns_cloudflare_email: johndoe@gmail.com
           srv_dyndns_cloudflare_token: supersecret
           srv_dyndns_domain: johndoe.com


## License

MIT


## Author Information

Created in 2020 by [IvanSible](https://github.com/ivansible)
