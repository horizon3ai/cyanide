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
import responder.utils as utils
import random
import sys
if (sys.version_info > (3, 0)):
	import configparser as ConfigParser
else:
	import ConfigParser
import subprocess

from responder.utils import *

__version__ = 'Responder 3.0.6.0'

class Settings:

	def __init__(self):
		self.ResponderPATH = os.path.dirname(__file__)
		self.Bind_To = '0.0.0.0'

	def __str__(self):
		ret = 'Settings class:\n'
		for attr in dir(self):
			value = str(getattr(self, attr)).strip()
			ret += "    Settings.%s = %s\n" % (attr, value)
		return ret

	def toBool(self, str):
		return str.upper() == 'ON'

	def ExpandIPRanges(self):
		def expand_ranges(lst):
			ret = []
			for l in lst:
				tab = l.split('.')
				x = {}
				i = 0
				for byte in tab:
					if '-' not in byte:
						x[i] = x[i+1] = int(byte)
					else:
						b = byte.split('-')
						x[i] = int(b[0])
						x[i+1] = int(b[1])
					i += 2
				for a in range(x[0], x[1]+1):
					for b in range(x[2], x[3]+1):
						for c in range(x[4], x[5]+1):
							for d in range(x[6], x[7]+1):
								ret.append('%d.%d.%d.%d' % (a, b, c, d))
			return ret

		self.RespondTo = expand_ranges(self.RespondTo)
		self.DontRespondTo = expand_ranges(self.DontRespondTo)

	def edit_local_responder_config(self, responder_blacklist, scope=None):
		responder_config = self.ResponderPATH + '/Responder.conf'
		os.system(f'sed -i "s/^DontRespondTo =.*/DontRespondTo = {responder_blacklist}/" {responder_config}')
		if scope:
			os.system(f'sed -i "s/^RespondTo =.*/RespondTo = {scope}/" {responder_config}')
		else:
			os.system(f'sed -i "s/^RespondTo =.*/RespondTo =/" {responder_config}')

	def populate(self, options, tool_q=None):

		if options.Interface is None and utils.IsOsX() is False:
			print(utils.color("Error: -I <if> mandatory option is missing", 1))
			sys.exit(-1)

		if options.Interface == "ALL" and options.OURIP == None:
			print(utils.color("Error: -i is missing.\nWhen using -I ALL you need to provide your current ip address", 1))
			sys.exit(-1)
		#Python version
		if (sys.version_info > (3, 0)):
			self.PY2OR3     = "PY3"
		else:
			self.PY2OR3	= "PY2"
		# Config parsing
		config = ConfigParser.ConfigParser()
		config.read(os.path.join(self.ResponderPATH, 'Responder.conf'))

		# Servers
		# create a list of enabled servers to track in Poisoner tool class
		# enables the tracking of modules that do not use ntlmrelayx and enables specific actions to take
		self.enabled_servers = []
		self.HTTP_On_Off     = self.toBool(config.get('Responder Core', 'HTTP'))
		if self.HTTP_On_Off:
			self.enabled_servers.append('HTTP')
		self.SSL_On_Off      = self.toBool(config.get('Responder Core', 'HTTPS'))
		if self.SSL_On_Off:
			self.enabled_servers.append('HTTPS')
		self.SMB_On_Off      = self.toBool(config.get('Responder Core', 'SMB'))
		if self.SMB_On_Off:
			self.enabled_servers.append('SMB')
		self.SQL_On_Off      = self.toBool(config.get('Responder Core', 'SQL'))
		if self.SQL_On_Off:
			self.enabled_servers.append('SQL')
		self.FTP_On_Off      = self.toBool(config.get('Responder Core', 'FTP'))
		if self.FTP_On_Off:
			self.enabled_servers.append('FTP')
		self.POP_On_Off      = self.toBool(config.get('Responder Core', 'POP'))
		if self.POP_On_Off:
			self.enabled_servers.append('POP')
		self.IMAP_On_Off     = self.toBool(config.get('Responder Core', 'IMAP'))
		if self.IMAP_On_Off:
			self.enabled_servers.append('IMAP')
		self.SMTP_On_Off     = self.toBool(config.get('Responder Core', 'SMTP'))
		if self.SMTP_On_Off:
			self.enabled_servers.append('SMTP')
		self.LDAP_On_Off     = self.toBool(config.get('Responder Core', 'LDAP'))
		if self.LDAP_On_Off:
			self.enabled_servers.append('LDAP')
		self.DNS_On_Off      = self.toBool(config.get('Responder Core', 'DNS'))
		if self.DNS_On_Off:
			self.enabled_servers.append('DNS')
		self.RDP_On_Off      = self.toBool(config.get('Responder Core', 'RDP'))
		if self.RDP_On_Off:
			self.enabled_servers.append('RDP')
		self.DCERPC_On_Off      = self.toBool(config.get('Responder Core', 'DCERPC'))
		if self.DCERPC_On_Off:
			self.enabled_servers.append('DCERPC')
		self.WinRM_On_Off      = self.toBool(config.get('Responder Core', 'WINRM'))
		if self.WinRM_On_Off:
			self.enabled_servers.append('WINRM')
		self.Krb_On_Off      = self.toBool(config.get('Responder Core', 'Kerberos'))
		if self.Krb_On_Off:
			self.enabled_servers.append('Kerberos')

		if tool_q != None:
			msg = {'poisoner': 'responder', 'action_state': 'enabled_servers', 'data': self.enabled_servers}
			tool_q.put_nowait(msg)

		# Db File
		self.DatabaseFile    = os.path.join(self.ResponderPATH, config.get('Responder Core', 'Database'))

		# Log Files
		self.LogDir = os.path.join(self.ResponderPATH, 'logs')

		if not os.path.exists(self.LogDir):
			os.mkdir(self.LogDir)

		self.SessionLogFile      = os.path.join(self.LogDir, config.get('Responder Core', 'SessionLog'))
		self.PoisonersLogFile    = os.path.join(self.LogDir, config.get('Responder Core', 'PoisonersLog'))
		self.AnalyzeLogFile      = os.path.join(self.LogDir, config.get('Responder Core', 'AnalyzeLog'))
		self.ResponderConfigDump = os.path.join(self.LogDir, config.get('Responder Core', 'ResponderConfigDump'))

		self.FTPLog          = os.path.join(self.LogDir, 'FTP-Clear-Text-Password-%s.txt')
		self.IMAPLog         = os.path.join(self.LogDir, 'IMAP-Clear-Text-Password-%s.txt')
		self.POP3Log         = os.path.join(self.LogDir, 'POP3-Clear-Text-Password-%s.txt')
		self.HTTPBasicLog    = os.path.join(self.LogDir, 'HTTP-Clear-Text-Password-%s.txt')
		self.LDAPClearLog    = os.path.join(self.LogDir, 'LDAP-Clear-Text-Password-%s.txt')
		self.SMBClearLog     = os.path.join(self.LogDir, 'SMB-Clear-Text-Password-%s.txt')
		self.SMTPClearLog    = os.path.join(self.LogDir, 'SMTP-Clear-Text-Password-%s.txt')
		self.MSSQLClearLog   = os.path.join(self.LogDir, 'MSSQL-Clear-Text-Password-%s.txt')

		self.LDAPNTLMv1Log   = os.path.join(self.LogDir, 'LDAP-NTLMv1-Client-%s.txt')
		self.HTTPNTLMv1Log   = os.path.join(self.LogDir, 'HTTP-NTLMv1-Client-%s.txt')
		self.HTTPNTLMv2Log   = os.path.join(self.LogDir, 'HTTP-NTLMv2-Client-%s.txt')
		self.KerberosLog     = os.path.join(self.LogDir, 'MSKerberos-Client-%s.txt')
		self.MSSQLNTLMv1Log  = os.path.join(self.LogDir, 'MSSQL-NTLMv1-Client-%s.txt')
		self.MSSQLNTLMv2Log  = os.path.join(self.LogDir, 'MSSQL-NTLMv2-Client-%s.txt')
		self.SMBNTLMv1Log    = os.path.join(self.LogDir, 'SMB-NTLMv1-Client-%s.txt')
		self.SMBNTLMv2Log    = os.path.join(self.LogDir, 'SMB-NTLMv2-Client-%s.txt')
		self.SMBNTLMSSPv1Log = os.path.join(self.LogDir, 'SMB-NTLMSSPv1-Client-%s.txt')
		self.SMBNTLMSSPv2Log = os.path.join(self.LogDir, 'SMB-NTLMSSPv2-Client-%s.txt')

		# HTTP Options
		self.Serve_Exe	      = self.toBool(config.get('HTTP Server', 'Serve-Exe'))
		self.Serve_Always     = self.toBool(config.get('HTTP Server', 'Serve-Always'))
		self.Serve_Html       = self.toBool(config.get('HTTP Server', 'Serve-Html'))
		self.Html_Filename    = config.get('HTTP Server', 'HtmlFilename')
		self.Exe_Filename     = config.get('HTTP Server', 'ExeFilename')
		self.Exe_DlName       = config.get('HTTP Server', 'ExeDownloadName')
		self.WPAD_Script      = config.get('HTTP Server', 'WPADScript')
		self.HtmlToInject     = config.get('HTTP Server', 'HtmlToInject')

		if self.Serve_Exe is True:
			if not os.path.exists(self.Html_Filename):
				print(utils.color("/!\ Warning: %s: file not found" % self.Html_Filename, 3, 1))

			if not os.path.exists(self.Exe_Filename):
				print(utils.color("/!\ Warning: %s: file not found" % self.Exe_Filename, 3, 1))

		# SSL Options
		self.SSLKey  = config.get('HTTPS Server', 'SSLKey')
		self.SSLCert = config.get('HTTPS Server', 'SSLCert')

		# Respond to hosts
		self.RespondTo         = list(filter(None, [x.upper().strip() for x in config.get('Responder Core', 'RespondTo').strip().split(',')]))
		self.RespondToName     = list(filter(None, [x.upper().strip() for x in config.get('Responder Core', 'RespondToName').strip().split(',')]))
		self.DontRespondTo     = list(filter(None, [x.upper().strip() for x in config.get('Responder Core', 'DontRespondTo').strip().split(',')]))
		self.DontRespondToName = list(filter(None, [x.upper().strip() for x in config.get('Responder Core', 'DontRespondToName').strip().split(',')]))

		#Generate Random stuff for one Responder session
		self.MachineName       = 'WIN-'+''.join([random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for i in range(11)])
		self.Domain            = ''.join([random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for i in range(4)])
		self.DomainName        = self.Domain + '.LOCAL'
		self.MachineNego       = ''.join([random.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for i in range(9)]) +'$@'+self.DomainName
		self.RPCPort           = random.randrange(45000, 49999)
		# Auto Ignore List
		self.AutoIgnore                       = self.toBool(config.get('Responder Core', 'AutoIgnoreAfterSuccess'))
		self.CaptureMultipleCredentials       = self.toBool(config.get('Responder Core', 'CaptureMultipleCredentials'))
		self.CaptureMultipleHashFromSameHost  = self.toBool(config.get('Responder Core', 'CaptureMultipleHashFromSameHost'))
		self.AutoIgnoreList                   = []

		# CLI options
		self.ExternalIP         = options.ExternalIP
		self.LM_On_Off          = options.LM_On_Off
		self.NOESS_On_Off       = options.NOESS_On_Off
		self.WPAD_On_Off        = options.WPAD_On_Off
		self.Wredirect          = options.Wredirect
		self.NBTNSDomain        = options.NBTNSDomain
		self.Basic              = options.Basic
		self.Finger_On_Off      = options.Finger
		self.Interface          = options.Interface
		self.OURIP              = options.OURIP
		self.Force_WPAD_Auth    = options.Force_WPAD_Auth
		self.Upstream_Proxy     = options.Upstream_Proxy
		self.AnalyzeMode        = options.Analyze
		self.Verbose            = options.Verbose
		self.ProxyAuth_On_Off   = options.ProxyAuth_On_Off
		self.CommandLine        = str(sys.argv)

		if self.ExternalIP:
			self.ExternalIPAton = socket.inet_aton(self.ExternalIP)

		if self.HtmlToInject is None:
			self.HtmlToInject = ''

		self.Bind_To         = utils.FindLocalIP(self.Interface, self.OURIP)

		if self.Interface == "ALL":
                	self.Bind_To_ALL  = True
		else:
			self.Bind_To_ALL  = False

		if self.Interface == "ALL":
			self.IP_aton   = socket.inet_aton(self.OURIP)
		else:
			self.IP_aton   = socket.inet_aton(self.Bind_To)

		self.Os_version      = sys.platform

		# Set up Challenge
		self.NumChal = config.get('Responder Core', 'Challenge')
		if self.NumChal.lower() == 'random':
			self.NumChal = "random"

		if len(self.NumChal) != 16 and self.NumChal != "random":
			print(utils.color("[!] The challenge must be exactly 16 chars long.\nExample: 1122334455667788", 1))
			sys.exit(-1)

		self.Challenge = b''
		if self.NumChal.lower() == 'random':
			pass
		else:
			if self.PY2OR3 == 'PY2':
				for i in range(0, len(self.NumChal),2):
					self.Challenge += self.NumChal[i:i+2].decode("hex")
			else:
					self.Challenge = bytes.fromhex(self.NumChal)


		# Set up logging
		logging.basicConfig(filename=self.SessionLogFile, level=logging.INFO, format='%(asctime)s - %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p')
		#logging.warning('Responder Started: %s' % self.CommandLine)

		Formatter = logging.Formatter('%(asctime)s - %(message)s')
		PLog_Handler = logging.FileHandler(self.PoisonersLogFile, 'w')
		ALog_Handler = logging.FileHandler(self.AnalyzeLogFile, 'a')
		PLog_Handler.setLevel(logging.INFO)
		ALog_Handler.setLevel(logging.INFO)
		PLog_Handler.setFormatter(Formatter)
		ALog_Handler.setFormatter(Formatter)

		self.PoisonersLogger = logging.getLogger('Poisoners Log')
		self.PoisonersLogger.addHandler(PLog_Handler)

		self.AnalyzeLogger = logging.getLogger('Analyze Log')
		self.AnalyzeLogger.addHandler(ALog_Handler)

		try:
			NetworkCard = subprocess.check_output(["ifconfig", "-a"])
		except:
			try:
				NetworkCard = subprocess.check_output(["ip", "address", "show"])
			except subprocess.CalledProcessError as ex:
				NetworkCard = "Error fetching Network Interfaces:", ex
				pass
		try:
			DNS = subprocess.check_output(["cat", "/etc/resolv.conf"])
		except subprocess.CalledProcessError as ex:
			DNS = "Error fetching DNS configuration:", ex
			pass
		try:
			RoutingInfo = subprocess.check_output(["netstat", "-rn"])
		except:
			try:
				RoutingInfo = subprocess.check_output(["ip", "route", "show"])
			except subprocess.CalledProcessError as ex:
				RoutingInfo = "Error fetching Routing information:", ex
				pass

		Message = "Current environment is:\nNetwork Config:\n%s\nDNS Settings:\n%s\nRouting info:\n%s\n\n"%(NetworkCard,DNS,RoutingInfo)
		try:
			utils.DumpConfig(self.ResponderConfigDump, Message)
			utils.DumpConfig(self.ResponderConfigDump,str(self))
		except AttributeError as ex:
			print("Missing Module:", ex)
			pass

def init():
	global Config
	Config = Settings()
