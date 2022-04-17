#!/usr/bin/python3

# Copyright (C) 2014-2015 Nginx, Inc.
# Copyright (c) 2022 sokolovmy@gmail.com

import argparse
import base64
from http.server import HTTPServer, BaseHTTPRequestHandler
import signal
import sys
import threading
from socketserver import ThreadingMixIn
from ldap3 import Server, Connection

class LdapAuthProxyServer(ThreadingMixIn, HTTPServer):
    pass

class AuthHandler(BaseHTTPRequestHandler):

    # Return True if request is processed and response sent, otherwise False
    # Set ctx['user'] and ctx['pass'] for authentication
    def do_GET(self):

        ctx = self.ctx

        ctx['action'] = 'input parameters check'
        for k, v in self.get_params().items():
            ctx[k] = self.headers.get(v[0], v[1])
            if ctx[k] == None:
                self.auth_failed(ctx, 'required "%s" header was not passed' % k)
                return True

        ctx['action'] = 'performing authorization'
        auth_header = self.headers.get('Authorization')

        if auth_header is None or not auth_header.lower().startswith('basic '):

            self.send_response(401)
            self.send_header('WWW-Authenticate', 'Basic realm="' + ctx['realm'] + '"')
            self.send_header('Cache-Control', 'no-cache')
            self.end_headers()

            return True

        ctx['action'] = 'decoding credentials'

        try:
            auth_decoded = base64.b64decode(auth_header[6:])
            auth_decoded = auth_decoded.decode("utf-8")
            user, passwd = auth_decoded.split(':', 1)

        except:
            self.auth_failed(ctx)
            return True

        ctx['user'] = user
        ctx['pass'] = passwd

        # Continue request processing
        return False

    # Log the error and complete the request with appropriate status
    def auth_failed(self, ctx, errmsg = None):

        msg = 'Error while ' + ctx['action']
        if errmsg:
            msg += ': ' + errmsg

        ex, value, trace = sys.exc_info()

        if ex != None:
            msg += ": " + str(value)

        if ctx.get('url'):
            msg += ', server="%s"' % ctx['url']

        if ctx.get('user'):
            msg += ', login="%s"' % ctx['user']

        self.log_error(msg)
        self.send_response(401)
        self.send_header('WWW-Authenticate', 'Basic realm="' + ctx['realm'] + '"')
        self.send_header('Cache-Control', 'no-cache')
        self.end_headers()

    def get_params(self):
        return {}

    def log_message(self, format, *args):
        if len(self.client_address) > 0:
            addr = BaseHTTPRequestHandler.address_string(self)
        else:
            addr = "-"

        if not hasattr(self, 'ctx'):
            user = '-'
        else:
            user = self.ctx['user']

        sys.stdout.write("%s - %s [%s] %s\n" % (addr, user,
                         self.log_date_time_string(), format % args))

    def log_error(self, format, *args):
        self.log_message(format, *args)




# Verify username/password against LDAP server
class LDAPAuthProxyHandler(AuthHandler):
    # Parameters to put into self.ctx from the HTTP header of auth request
    params =  {
            # parameter      header         default
            'realm': ('X-Ldap-Realm', 'Restricted'),
            'ldap_server': ('X-Ldap-Server', 'localhost'),
            'ldap_use_ssl': ('X-Ldap-SSL', True),
            'ldap_domain': ('X-Ldap-Domain', '')
        }

    @classmethod
    def set_params(cls, params):
        cls.params = params

    def get_params(self):
        return self.params

    # GET handler for the authentication request
    def do_GET(self):

        ctx = dict()
        self.ctx = ctx

        ctx['action'] = 'initializing basic auth handler'
        ctx['user'] = '-'

        if AuthHandler.do_GET(self):
            # request already processed
            return

        ctx['action'] = 'empty password check'
        if not ctx['pass']:
            self.auth_failed(ctx, 'attempt to use empty password')
            return

        try:
            if not ctx['ldap_server']:
                self.log_message('LDAP Server is not set!')
                return

            ctx['action'] = 'initializing LDAP connection'
            with Connection(
                    Server(ctx['ldap_server'], use_ssl=ctx['ldap_use_ssl']),
                    user=f"{ctx['user']}@{ctx['ldap_domain']}",
                    password=ctx['pass'],
            ) as conn:
                if conn.bind():
                    self.log_message('Auth OK for user "%s"' % (ctx['user']))

                    # Successfully authenticated user
                    self.send_response(200)
                    self.send_header('content-type','text/html')
                    self.end_headers()
                    # self.wfile.write("User OK!")
                else:
                    self.auth_failed(ctx)

        except:
            self.auth_failed(ctx)


def arg_parser():
    parser = argparse.ArgumentParser(
        description="LDAP Authentication Proxy.")
    # Group for listen options:
    group = parser.add_argument_group("Listen options")
    group.add_argument('-H', '--host',  metavar="hostname",
        default="0.0.0.0", help="host to bind (Default: 0.0.0.0)")
    group.add_argument('-p', '--port', metavar="port", type=int,
        default=8080, help="port to bind (Default: 8080)")
    # ldap options:
    group = parser.add_argument_group(title="LDAP options")
    group.add_argument('-l', '--ldap-server', metavar="ldap_server",
        default="localhost",
        help=("LDAP Server (Default: localhost)"))
    group.add_argument('--not-use-ssl', action='store_true',
        help=("Do not use SSL when connecting to Ldap Server"))
    group.add_argument('-d', '--ldap-domain', metavar="ldap_domain",
        help=("Sets default domain for user"))
    # http options:
    group = parser.add_argument_group(title="HTTP options")
    group.add_argument('-r', '--realm', metavar='"Restricted Area"',
        default="Restricted", help='HTTP auth realm (Default: "Restricted")')

    args = parser.parse_args()
    listen = (args.host, args.port)
    params = {
             'realm': ('X-Ldap-Realm', args.realm),
             'ldap_server': ('X-Ldap-Server', args.ldap_server),
             'ldap_use_ssl': ('X-Ldap-SSL', not args.not_use_ssl),
             'ldap_domain': ('X-Ldap-Domain', args.ldap_domain)
    }
    return listen, params
 
def exit_handler(signal, frame):
    sys.stdout.write("Server stopped\n")
    sys.stdout.flush()
    sys.exit(0)

if __name__ == '__main__':
    listen, params = arg_parser()

    LDAPAuthProxyHandler.set_params(params)
    server = LdapAuthProxyServer(listen, LDAPAuthProxyHandler)
    signal.signal(signal.SIGINT, exit_handler)
    signal.signal(signal.SIGTERM, exit_handler)

    sys.stdout.write("Start listening on %s:%d...\n" % listen)
    sys.stdout.flush()
    print(listen)
    print(params)
    server.serve_forever()
