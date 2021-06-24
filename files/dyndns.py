#!/usr/local/dyndns/bin/python3

import os
import sys
import pwd
import grp
import re
import time
import base64
import traceback
import io
import threading
import _thread
import gc
import paramiko
import subprocess
import shlex
import configparser

from CloudFlare import CloudFlare
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

CONFIG_FILE = "/etc/dyndns.conf"
CONFIG_SECT = "dyndns"

PROBE_SCRIPT = """#!/bin/sh
#set -x
PATH=/opt/sbin:/opt/bin
prefix_len=%s
prefix_dev=%s
[ -f /opt/etc/net/config ] && . /opt/etc/net/config
ipv4=$(curl -4sk https://ipv4.icanhazip.com)
ipv6=$(curl -6sk https://ipv6.icanhazip.com)
pfx6=$(ip -o -6 route show dev ${prefix_dev} |
       awk "/:\\/${prefix_len}/ && !/^ff00|^fe80/ {print \\$1; exit}")
echo "ipv4=$ipv4 ipv6=$ipv6 pfx6=$pfx6"
"""


class DDNS(object):

    SSH_KEY_TYPES = (
        paramiko.ed25519key.Ed25519Key,
        paramiko.ecdsakey.ECDSAKey,
        # paramiko.dsskey.DSSKey,
        paramiko.rsakey.RSAKey,
    )

    RETRY_COUNT = 6
    RETRY_SLEEP = 15
    TEST_HANDLERS = False

    stdlog = sys.stdout

    def main(self, argv=sys.argv):
        self.is_service = False
        self.web_active = False
        self.poll_active = False
        self.cf_dns = None

        mode = argv[1] if len(argv) == 2 else ''
        try:
            if mode == 'update':
                self.setup()
                self.update_once()
            elif mode == 'web':
                self.setup()
                self.web_server()
            elif mode == 'poll':
                self.setup()
                self.poll_service()
            elif mode == 'service':
                self.is_service = True
                self.setup()
                poll_thread = threading.Thread(target=self.poll_service)
                poll_thread.daemon = True
                poll_thread.start()
                self.web_server()
            else:
                program = os.path.basename(argv[0])
                print('usage: %s service|web|poll|update' % program,
                      file=sys.stderr)
                sys.exit(1)
        except RuntimeError as ex:
            print('exception: %s' % ex, file=sys.stderr)
            sys.exit(1)

    def web_server(self):
        listen = ('', int(self.param('web_port')))
        server = HTTPServer(listen, DDNSRequestHandler)
        try:
            self.web_active = True
            self.message('server started')
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        except RuntimeError as ex:
            self.error('exception: %s', ex)
        finally:
            server.server_close()
            self.web_active = False
            self.poll_active = False
            self.message('bye')

    def poll_service(self):
        if self.poll_interval <= 0:
            self.message('poll disabled')
            return

        self.poll_active = True
        time.sleep(0.5)
        while self.poll_active:
            try:
                self.message('next poll')
                self.update_once()
                if self.is_service and self.cf_dns:
                    self.cf_dns = None
                    gc.collect()
                time.sleep(self.poll_interval)
            except KeyboardInterrupt:
                if self.web_active:
                    _thread.interrupt_main()
                break
            except Exception as ex:
                self.error('exception: %s', ex)
                if self.verbose >= 2 and not isinstance(ex, RuntimeError):
                    trace = traceback.format_exc()
                    self.stdlog.write(trace)
                    self.stdlog.flush()

    def update_once(self):
        ipv4, ipv6, pfx6, changed = \
            self.handle_request(self.main_host, '', False)
        if ipv4 and ipv6 and pfx6:
            probe_changed = False
        else:
            ipv4, ipv6, pfx6, probe_changed = self.probe_addr()
        if changed or probe_changed:
            self.run_commands(ipv4, pfx6 or ipv6)
        self.message('ipv4 %s ipv6 %s prefix6 %s',
                     ipv4, ipv6, pfx6, verbose=3)

    def handle_request(self, host, addr, via_web):
        if not self.cf_dns:
            self.setup_cloudflare()

        pfx6, pfx_changed = None, False
        ipv4, ipv6 = '', ''

        if ':' in addr:
            ipv6 = addr
        else:
            ipv4 = addr

        if host == self.main_host:
            ipv4_probe, ipv6_probe, pfx6, pfx_changed = self.probe_addr()
            ipv4 = ipv4 or ipv4_probe
            ipv6 = ipv6 or ipv6_probe

        ipv4_changed = self.update_host(host, ipv4, ipv6=False)
        ipv6_changed = self.update_host(host, ipv6, ipv6=True)
        changed = (ipv4_changed or ipv6_changed or pfx_changed
                   or self.TEST_HANDLERS)

        if host == self.main_host and changed and via_web:
            self.run_commands(ipv4, pfx6 or ipv6)

        if via_web and self.is_service:
            self.cf_dns = None
            gc.collect()

        return (ipv4, ipv6, pfx6, changed)

    def setup(self):
        self.config = configparser.ConfigParser()
        config_file = os.environ.get('DYNDNS_CONFIG_FILE', CONFIG_FILE)
        self.config.read(config_file)
        if not self.config.has_section(CONFIG_SECT):
            print('failed to parse config: %s' % config_file, file=sys.stderr)
            sys.exit(1)

        self.verbose = int(self.param('verbose', '0'))

        username = self.param('web_user', 'dyndns')
        password = self.param('web_pass')
        user_pass = bytes('%s:%s' % (username, password), 'utf-8')
        self.web_auth = 'Basic ' + base64.b64encode(user_pass).decode('utf-8')

        self.web_path = self.param('web_path', '/dyndns').rstrip('/')

        self.poll_interval = int(self.param('poll_interval', 3600))
        self.timeout = int(self.param('timeout', 5))

        self.domain = self.param('domain').strip('.')

        hostname = self.param('main_host', required=False)
        if '.' in hostname:
            self.fatal('hostname %s must not be fully qualified', hostname)
        if hostname:
            self.main_host = '%s.%s' % (hostname, self.domain)
        else:
            self.main_host = ''

        self.setup_commands()
        self.setup_prober()
        self.setup_cloudflare()

        # drop privileges
        if os.getuid() == 0:
            os.setgroups([])
            os.setgid(grp.getgrnam('nogroup').gr_gid)
            os.setuid(pwd.getpwnam('nobody').pw_uid)

    def message(self, format, *args, **kwargs):
        verbose = kwargs.pop('verbose', 2)
        if self.verbose < verbose:
            return
        msg = format % args
        if not self.is_service:
            now = time.time()
            yy, mm, dd, h, m, s, _, _, _ = time.localtime(now)
            ts = '%02d-%02d-%02d %02d:%02d:%02d' % (yy, mm, dd, h, m, s)
            msg = '[%s] %s' % (ts, msg)
        self.stdlog.write('%s\n' % msg)
        self.stdlog.flush()

    def error(self, format, *args, **kwargs):
        kwargs.setdefault('verbose', 1)
        self.message('error: ' + format, *args, **kwargs)

    def fatal(self, format, *args, **kwargs):
        msg = format % args
        self.stdlog.write('fatal: %s\n' % msg)
        self.stdlog.flush()
        if self.web_active:
            _thread.interrupt_main()
        sys.exit(1)

    def param(self, name, fallback='', required=True):
        value = self.config.get(CONFIG_SECT, name, fallback=fallback, raw=True)
        if required and not value:
            self.fatal('missing variable: %s', name)
        return value

    def setup_cloudflare(self):
        cf_email = self.param('cloudflare_email')
        cf_token = self.param('cloudflare_token')
        cf_debug = self.verbose >= 4
        cf = CloudFlare(email=cf_email, token=cf_token, debug=cf_debug)

        zones = cf.zones.get(params=dict(name=self.domain, per_page=1))
        if not zones:
            self.fatal('invalid zone: %s', self.domain)

        self.zone_id = zones[0]['id']
        self.cf_dns = cf.zones.dns_records

    def update_host(self, host, addr, ipv6):
        if not host or not addr:
            return False

        zone_domain = '.' + self.domain
        if not host.endswith(zone_domain):
            self.error('host %s not in zone %s', host, self.domain)
            return False
        name = host[:-len(zone_domain)].strip('.')
        if not name:
            self.error('host without name %s', host)
            return False

        rtype = 'AAAA' if ipv6 else 'A'
        new_rec = dict(name=host, type=rtype, content=addr, proxied=False)

        params = dict(name=host, match='all', type=rtype)
        records = self.cf_dns.get(self.zone_id, params=params)

        found = False
        changed = False

        for rec in records:
            if rec['type'] != rtype:
                continue
            found = True

            if rec['content'] == addr and not rec['proxied']:
                self.message('keep %s as %s (%s)', host, addr, rtype,
                             verbose=3)
                continue

            self.message('update %s as %s (%s)', host, addr, rtype)
            self.cf_dns.put(self.zone_id, rec['id'], data=new_rec)
            changed = True

        if not found:
            self.message('create %s as %s (%s)', host, addr, rtype)
            self.cf_dns.post(self.zone_id, data=new_rec)
            changed = True

        return changed

    def setup_commands(self):
        node_hosts = self.param('node_hosts', required=False).strip()
        if node_hosts:
            self.node_hosts = [self.ssh_parse_url(url.strip())
                               for url in re.split(r'[,\s]+', node_hosts)
                               if url.strip()]
        else:
            self.node_hosts = None
        self.node_cmd = self.param('node_cmd', required=False).strip()
        self.main_cmd = self.param('main_cmd', required=False).strip()

    def run_commands(self, ipv4=None, ipv6=None):
        self._run_cmd('node_cmd', self.node_cmd, self.node_hosts, ipv4, ipv6)
        self._run_cmd('main_cmd', self.main_cmd, [self.ssh_conn], ipv4, ipv6)

    def _run_cmd(self, name, cmd, hosts, ipv4, ipv6):
        if not cmd:
            return
        cmd = cmd.replace('{ipv4}', ipv4 or '127.0.0.1')
        cmd = cmd.replace('{ipv6}', ipv6 or '::1')

        if not hosts:
            proc = subprocess.Popen(
                shlex.split(cmd), close_fds=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = proc.communicate()
            str_out = stdout.decode('utf-8', 'replace').replace('\n', ' ... ')
            str_err = stderr.decode('utf-8', 'replace').replace('\n', ' ... ')
            if proc.returncode or str_err:
                self.error('%s[local] failed: %s', name, str_err or '?')
            elif str_out and self.verbose >= 2:
                self.message('%s[local] output: %s', name, str_out)
            return

        threads = [threading.Thread(target=self._remote_cmd,
                                    args=(conn, cmd, name))
                   for conn in hosts]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    def _remote_cmd(self, conn, cmd, name):
        host = conn['host']
        try:
            strout, strerr = self.exec_command(conn, cmd)
            if strerr:
                self.error('%s[%s] failed: %s', name, host, strerr)
            elif strout and self.verbose >= 2:
                self.message('%s[%s] output: %s', name, host, strout)
        except RuntimeError as e:
            self.error("%s[%s]: ssh failed: %s", name, host, e)
            return

    def setup_prober(self):
        url = self.param('ssh_url', required=False)
        self.ssh_conn = self.ssh_parse_url(url) if url else None

        self.prefix_len = int(self.param('prefix_len', required=False) or 0)
        self.prefix_dev = self.param('prefix_dev', required=False)

        self.prefix_hosts = []
        prefix_hosts = self.param('prefix_hosts', required=False).strip()
        for item in re.split(r'[,\s]+', prefix_hosts):
            if not item.strip():
                continue
            host, addr = None, None
            tokens = item.strip().split('=')
            if len(tokens) == 2:
                host = tokens[0].strip()
                addr = tokens[1].strip().lower()
                if '.' in host:
                    host = None
                if not re.match(r'^[0-9a-f][0-9a-f:]+[0-9a-f]$', addr):
                    addr = None
            if host and addr:
                self.prefix_hosts.append((host, addr.strip(':')))
            else:
                self.fatal('invalid prefix hosts: %s', prefix_hosts)

    def ssh_parse_url(self, url, schemes=None):
        parsed_url = urlparse(url)
        query_args = parse_qs(parsed_url.query)

        if url and schemes and parsed_url.scheme not in schemes:
            self.fatal('ssh schema must be one of: %s', ' '.join(schemes))

        conn = {
            'url': url,
            'scheme': parsed_url.scheme,
            'host': parsed_url.hostname,
            'port': int(parsed_url.port or 22),
            'user': parsed_url.username,
            'pass': parsed_url.password or None,
        }

        key_file = query_args.get('keyfile', [''])[0]
        key_str = query_args.get('keystr', [''])[0].strip().replace(',', '\n')
        if not key_str and key_file:
            try:
                key_file = os.path.expanduser(key_file)
                with open(key_file) as f:
                    key_str = f.read().strip()
            except IOError:
                self.fatal('error reading ssh key: %s', key_file)

        key = None
        if key_str:
            exception = None
            for key_type in self.SSH_KEY_TYPES:
                try:
                    key = key_type.from_private_key(io.StringIO(key_str))
                except paramiko.SSHException as ex:
                    exception = ex
                if key:
                    break
            if not key:
                self.fatal('invalid ssh key: %s', exception)

        conn['key_file'] = key_file
        conn['key'] = key

        # validate connection
        ssh = self.ssh_connect(conn)
        ssh.close()
        return conn

    def ssh_connect(self, conn):
        msg = '%(host)s,%(port)s (%(user)s)' % conn
        for retry in range(self.RETRY_COUNT):
            if retry > 0:
                self.error('retry ssh login: %s', msg)
            try:
                ssh = paramiko.SSHClient()
                ssh.load_system_host_keys()
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                ssh.connect(hostname=conn['host'], port=conn['port'],
                            username=conn['user'], password=conn['pass'],
                            pkey=conn['key'], timeout=self.timeout)
                return ssh
            except Exception:
                try:
                    ssh.close()
                except Exception:
                    pass
            time.sleep(self.RETRY_SLEEP)
        raise RuntimeError('ssh login failed: %s' % msg)

    def exec_command(self, conn, cmd):
        ssh = None
        try:
            ssh = self.ssh_connect(conn)
            stdin, stdout, stderr = ssh.exec_command(cmd)
            strout = ' ... '.join(ln.strip() for ln in stdout.readlines())
            strerr = ' ... '.join(ln.strip() for ln in stderr.readlines())
            cmd_msg = cmd.replace('\n', ' ... ')
            self.message("ssh: host '%s' cmd '%s' stdout '%s' stderr '%s'",
                         conn['host'], cmd_msg, strout, strerr, verbose=3)
            return strout, strerr
        finally:
            if ssh:
                ssh.close()

    def probe_addr(self):
        cmd = PROBE_SCRIPT % (self.prefix_len, self.prefix_dev)
        strout, strerr = self.exec_command(self.ssh_conn, cmd)
        match = re.match(
            r'^ipv4=([0-9.]+) ipv6=([0-9a-f:]+) pfx6=([0-9a-f:/]+)$',
            strout)
        if not match:
            self.error('address probe failed: %s', strerr)
            return None, None, None, False
        ipv4, ipv6, prefix = match.group(1), match.group(2), match.group(3)

        if '/' in prefix:
            full_prefix = prefix
            pure_prefix = prefix.split('/')[0].strip(':')
        else:
            pure_prefix = prefix.strip(':')
            full_prefix = pure_prefix
            if '::' not in full_prefix:
                full_prefix += '::'
            full_prefix += '/%s' % (self.prefix_len or 64)
        if '::' in pure_prefix:
            pure_prefix = prefix.split('::')[0].strip(':')
        prefix_parts = len(pure_prefix.split(':'))

        change_count = 0
        for host, addr in self.prefix_hosts:
            full_host = '%s.%s' % (host, self.domain)
            addr_parts = len(addr.strip(':').split(':'))
            if prefix_parts + addr_parts > 8:
                self.error('invalid addr %s for prefix %s', addr, prefix)
                continue
            delimiter = '::' if prefix_parts + addr_parts < 8 else ':'
            full_addr = pure_prefix + delimiter + addr
            changed = self.update_host(full_host, full_addr, ipv6=True)
            if changed:
                change_count += 1

        self.message('%d of %d hosts updated for prefix %s',
                     change_count, len(self.prefix_hosts), prefix)
        return (ipv4, ipv6, full_prefix, change_count > 0)


class DDNSRequestHandler(BaseHTTPRequestHandler):

    def __init__(self, *args, **kwargs):
        global ddns
        self.ddns = ddns
        super().__init__(*args, **kwargs)

    def log_request(self, code='-', size='-'):
        if self.ddns.verbose >= 3:
            super().log_request(code, size)

    def log_message(self, format, *args, **kwargs):
        self.ddns.message(format, *args, **kwargs)

    def log_error(self, format, *args, **kwargs):
        self.ddns.error(format, *args, **kwargs)

    def send_error(self, format, *args, **kwargs):
        error = kwargs.pop('error', 'abuse')
        self.ddns.error(format, *args, **kwargs)
        self.send_reply(error)

    def send_reply(self, text):
        self.ddns.message('reply: %s', text, verbose=3)
        byte_reply = bytes(text + '\n', 'utf-8')
        self.send_response(200)
        self.send_header('Accept', '*/*')
        self.send_header('Content-type', 'text/plain')
        self.send_header('Content-Length', str(len(byte_reply)))
        self.end_headers()
        self.wfile.write(byte_reply)

    def do_GET(self):
        auth = self.headers.get('Authorization')
        if auth != self.ddns.web_auth:
            self.send_error('auth: %s', auth, error='badauth')
            return

        parsed_url = urlparse(self.path)
        query_args = parse_qs(parsed_url.query)

        path = parsed_url.path.rstrip('/')
        if path != self.ddns.web_path:
            self.send_error('invalid path %s', path)
            return

        addr = query_args.get('myip', [''])[0]
        if not addr:
            addr = self.headers.get('X-Real-IP', self.client_address[0])
        if not re.match(r'^([0-9]{1,3}\.){3}[0-9]{1,3}$', addr):
            self.send_error('invalid client addr %s', path)
            return

        host = query_args.get('hostname', [''])[0].strip('.')
        if not host:
            self.send_error('no host provided', error='nohost')
            return
        if not host.endswith('.' + self.ddns.domain):
            self.send_error('invalid host %s', host, error='notfqdn')
            return

        try:
            self.ddns.message('web request from %s', addr)
            changed = self.ddns.handle_request(host, addr, True)
            self.send_reply('good' if changed else 'nochg')
        except Exception as ex:
            self.send_error('exception: %s', ex, error='911')
            if isinstance(ex, RuntimeError):
                self.ddns.error('exception: %s', ex)
            elif self.ddns.verbose >= 2:
                trace = traceback.format_exc()
                self.ddns.stdlog.write(trace)
                self.ddns.stdlog.flush()


if __name__ == '__main__':
    ddns = DDNS()
    ddns.main()
    sys.exit(0)
