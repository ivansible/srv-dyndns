#!/usr/bin/python3

import os
import sys
import re
import time
import base64
import requests
import traceback
import io
import threading
import _thread
import gc
import paramiko
import subprocess
import shlex

from CloudFlare import CloudFlare
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from requests.exceptions import RequestException


class DDNS(object):

    SSH_METHODS = {
        'ssh-cli': 'cli',
        'ssh-openwrt': 'openwrt',
    }
    SSH_KEY_TYPES = (
        paramiko.ed25519key.Ed25519Key,
        paramiko.ecdsakey.ECDSAKey,
        # paramiko.dsskey.DSSKey,
        paramiko.rsakey.RSAKey,
    )

    PREFIX_CMD_CLI = 'show ipv6 prefix'
    PREFIX_CMD_OPENWRT = '/opt/sbin/ip -o -6 route show'

    SLEEP_INTERVAL = 5
    RETRY_COUNT = 5
    RETRY_SLEEP = 5
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
        time.sleep(0.1)
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
        addr_changed, ipv4, ipv6, prefix6 = \
            self.handle_request(self.main_host, '', False)
        if prefix6:
            prefix_changed = addr_changed
        else:
            prefix_changed, prefix6 = self.update_ipv6_prefix()
        if addr_changed or prefix_changed:
            self.run_command(ipv4, prefix6 or ipv6)

    def handle_request(self, host, addr, via_web):
        ipv4, ipv6 = '', ''
        if ':' in addr:
            ipv6 = addr
        else:
            ipv4 = addr

        if host == self.main_host and self.proxy:
            ipv4 = ipv4 or self.detect_address(ipv6=False)
            ipv6 = ipv6 or self.detect_address(ipv6=True)

        if not self.cf_dns:
            self.setup_cloudflare()

        ipv4_changed = self.update_host(host, ipv4, ipv6=False)
        ipv6_changed = self.update_host(host, ipv6, ipv6=True)
        addr_changed = ipv4_changed or ipv6_changed or self.TEST_HANDLERS

        if host == self.main_host and addr_changed and via_web:
            prefix_changed, prefix6 = self.update_ipv6_prefix()
            self.run_command(ipv4, prefix6 or ipv6)
        else:
            prefix6 = None
            prefix_changed = False

        if via_web and self.is_service:
            self.cf_dns = None
            gc.collect()

        return addr_changed or prefix_changed, ipv4, ipv6, prefix6

    def setup(self):
        self.verbose = int(self.param('verbose', '0'))

        username = self.param('web_user', 'dyndns')
        password = self.param('web_pass')
        user_pass = bytes('%s:%s' % (username, password), 'utf-8')
        self.web_auth = 'Basic ' + base64.b64encode(user_pass).decode('utf-8')

        self.web_path = self.param('web_path', '/dyndns').rstrip('/')

        self.poll_interval = int(self.param('poll_interval', 3600))
        self.timeout = int(self.param('timeout', 5))

        self.domain = self.param('domain').strip('.')
        self.proxy = self.param('main_proxy', required=False)

        hostname = self.param('main_host', required=False)
        if '.' in hostname:
            self.fatal('hostname %s must not be fully qualified', hostname)
        if hostname:
            self.main_host = '%s.%s' % (hostname, self.domain)
        else:
            self.main_host = ''

        self.setup_command()
        self.setup_prefix_updater()
        self.setup_cloudflare()

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

    def param(self, name, default='', required=True):
        name = 'DDNS_' + name.upper()
        value = os.environ.get(name, default)
        if required and not value:
            self.fatal('missing variable: %s', name)
        return value

    def detect_address(self, ipv6=False):
        if not self.proxy:
            return

        url = 'https://%s.icanhazip.com' % ('ipv6' if ipv6 else 'ipv4')
        proxies = dict(http=self.proxy, https=self.proxy)

        for retry in range(self.RETRY_COUNT):
            try:
                resp = requests.get(url, proxies=proxies, timeout=self.timeout)
                return resp.text.strip()
            except RequestException as ex:
                self.error('ip probe failed (%d of %d): %s',
                           retry + 1, self.RETRY_COUNT, ex)
                time.sleep(self.RETRY_SLEEP)
        return ''

    def setup_cloudflare(self):
        cf_email = self.param('cloudflare_email')
        cf_token = self.param('cloudflare_token')
        cf_debug = self.verbose >= 3
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

    def setup_command(self):
        self.command = self.param('command', required=False) or ''
        host_urls = self.param('cmd_hosts', required=False).strip()
        if host_urls:
            self.cmd_hosts = [self.ssh_parse_url(url.strip(), ['ssh'])
                              for url in re.split(r'[,\s]+', host_urls)
                              if url.strip()]
        else:
            self.cmd_hosts = None

    def run_command(self, ipv4=None, ipv6=None):
        cmd = self.command
        if not cmd:
            return
        cmd = cmd.replace('{ipv4}', ipv4 or '127.0.0.1')
        cmd = cmd.replace('{ipv6}', ipv6 or '::1')

        if not self.cmd_hosts:
            proc = subprocess.Popen(
                shlex.split(cmd), close_fds=True,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = proc.communicate()
            str_out = stdout.decode('utf-8', 'replace').replace('\n', ' ... ')
            str_err = stderr.decode('utf-8', 'replace').replace('\n', ' ... ')
            if proc.returncode or str_err:
                self.error('cmd[local] failed: %s', str_err or '?')
            elif str_out and self.verbose >= 2:
                self.message('cmd[local] output: %s', str_out)
            return

        threads = [threading.Thread(target=self.remote_cmd, args=(conn, cmd))
                   for conn in self.cmd_hosts]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    def remote_cmd(self, conn, cmd):
        host = conn['host']
        ssh, ex = self.ssh_connect(conn)
        if ex:
            self.error("cmd[%s]: ssh failed: %s", host, ex)
            return
        try:
            stdin, stdout, stderr = ssh.exec_command(cmd)
            str_out = ' ... '.join(ln.strip() for ln in stdout.readlines())
            str_err = ' ... '.join(ln.strip() for ln in stderr.readlines())
            if str_err:
                self.error('cmd[%s] failed: %s', host, str_err)
            elif str_out and self.verbose >= 2:
                self.message('cmd[%s] output: %s', host, str_out)
        finally:
            ssh.close()

    def setup_prefix_updater(self):
        self.prefix_len = int(self.param('prefix_len', required=False) or 0)
        self.prefix_interface = self.param('prefix_interface', required=False)

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

        url = self.param('ssh_url', required=False)
        if url:
            self.ssh_conn = self.ssh_parse_url(url, self.SSH_METHODS.keys())
            self.ssh_method = self.SSH_METHODS[self.ssh_conn['scheme']]
        else:
            self.ssh_conn = None
            self.ssh_method = None

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
        ssh, ex = self.ssh_connect(conn)
        if ssh:
            ssh.close()
            return conn
        else:
            raise ex

    def ssh_connect(self, conn):
        try:
            ssh = paramiko.SSHClient()
            ssh.load_system_host_keys()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=conn['host'], port=conn['port'],
                        username=conn['user'], password=conn['pass'],
                        pkey=conn['key'], timeout=self.timeout)
            return ssh, None
        except Exception:
            try:
                ssh.close()
            except Exception:
                pass
            msg = 'ssh login failed: %(host)s,%(port)s (%(user)s)' % conn
            return None, RuntimeError(msg)

    def detect_ipv6_prefix_cli(self, ssh):
        stdin, stdout, stderr = ssh.exec_command(self.PREFIX_CMD_CLI)

        prefix = ''
        ending = '/%d' % self.prefix_len if self.prefix_len else ''

        for line in list(stdout.readlines()):
            tokens = line.strip().split(' ')
            if len(tokens) != 2:
                continue
            key, val = tokens
            key = key.strip(':').lower()
            if not (key and val):
                continue

            if key == 'prefix':
                if ending and not val.endswith(ending):
                    continue
                prefix = val
                if not self.prefix_interface:
                    break
            elif key == 'interface':
                if self.prefix_interface and val == self.prefix_interface:
                    if prefix:
                        break
                    else:
                        prefix = val

        return prefix

    def detect_ipv6_prefix_openwrt(self, ssh):
        stdin, stdout, stderr = ssh.exec_command(self.PREFIX_CMD_OPENWRT)
        ending = '/%d' % self.prefix_len if self.prefix_len else ''

        for line in list(stdout.readlines()):
            tokens = [t.lower().strip() for t in line.strip().split()]
            if len(tokens) < 3:
                continue
            if tokens[0].startswith(('ff', 'fe')):
                continue
            if ending and not tokens[0].endswith(ending):
                continue
            if tokens[1] != 'dev':
                continue
            if self.prefix_interface and tokens[2] != self.prefix_interface:
                continue
            return tokens[0]

        return ''

    def update_ipv6_prefix(self):
        if not self.ssh_method:
            return

        ssh, ex = self.ssh_connect(self.ssh_conn)
        if ex:
            raise ex

        prefix = ''
        try:
            if self.ssh_method == 'cli':
                prefix = self.detect_ipv6_prefix_cli(ssh)
            elif self.ssh_method == 'openwrt':
                prefix = self.detect_ipv6_prefix_openwrt(ssh)
        finally:
            ssh.close()
        if not prefix:
            self.error('cannot detect prefix')
            return

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
        return change_count > 0, full_prefix


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
