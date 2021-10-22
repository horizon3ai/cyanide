# What is Cyanide?
As the name suggests, it's poison.  Cyanide is essentially a tracker for correlating various poisoning techniques (currently only Responder is used) in conjuction with relaying the captured hashes via Impackets ntlmrelayx.py.  On startup it will start Responder without SMB, HTTP, or DNS servers & Ntlmrelayx with SMB and HTTP servers by default. The output will inform you of:
 
1. Source poisoning
   - Poisoner (e.g. responder)
   - Poison method (e.g. LLMNR, NBT-NS, MDNS)
   - Host poisoned
   - Timestamp host was poisoned
   - Request
   - Protocol (e.g. SMB, MSSQL, etc.)
   - Username captured
   - Hash captured
   - Type of hash captured (e.g. cleartext, ntlmv2, etc.)
2. Relay Target
   - Target Host
   - Username used
   - Hash used
   - Results (hash captured, secretsdump output)
 
A mandatory file for ntlmrelayx targets is <b>_required_</b>.  If you only want to capture hashes, simply put smb://127.0.0.1, otherwise supply a list of targets as you normally would (e.g. smb://10.0.0.8\n mssql://10.0.0.9)
 
There is a couple ways it can be used. 
 
## Method 1 Poisoning + Relaying:
 
  The recommended method.  This method will utilize hashes captured via SMB/HTTP and relay them to targets specified in the targets file.  Upon successful relay, a secretsdump will be ran and SAM will (hopefully) get dumped.  
	
  For a successful login the target endpoint will need to have smb signing disabled.
___
## Method 2 Poisoning - Relaying

This method will continue to poison hosts via Responder, but will not relay.  In order to continue to capture SMB / HTTP, you will need to specify a host of <b>smb://127.0.0.1</b> in the required ntlmrelayx targets file.
___
 ## Usage:

```
python3 -m venv venv
. venv/bin/activate
git clone https://github.com/horizon3ai/cyanide.git
cd cyanide
pip install -r requirements.txt
sudo -i (must be ran under root account)
```

#### Relaying print to stdout:
1. vim ntlmrelayx_targets.txt
2. Put targets in format of <protocol>://<ip_address>
	- smb://192.168.1.1
	- mssql://192.168.1.2

`python cyanide.py -iface <eth0> --watch --stdout-only --responder -ntf ntlmrelayx_targets.txt`

<b>NOTE</b>: --watch/-w will allow you to edit the targets file while the program is running and add/delete targets.  Impacket will automatically detect changes and update.

#### No relaying print to stdout:
1. vim ntlmrelayx_targets.txt
2. Put a loopback target in format of smb://127.0.0.1
3. If you specify --stdout-only, cyanide will print out each hash that is captured to stdout, as well as any relay events and final messages
	
`python cyanide.py -iface <eth0> --stdout-only --responder -ntf ntlmrelayx_targets.txt --no-relay`

#### Relaying utilizing databases:

Cyanide utilizes sqlite databases to store information of hosts that are poisoned (poisoner_cache.db), relays that happen (poisoner_relay.db) and (if you do not specify --stdout-only) final messages containing poisoner source, relay events, secretsdump data will be placed in the production database (poisoner_prod.db).  The poisoner_prod.db will be dumped to a specified output file every 30 seconds.  <b>NOTE</b>: This means that the results will be overwritten every 30 seconds.


1. vim ntlmrelayx_targets.txt
2. Put targets in format of <protocol>://<ip_address>
	- smb://192.168.1.1
	- mssql://192.168.1.2
	
`python cyanide.py -iface <eth0> --watch --responder -ntf ntlmrelayx_targets.txt`
	
#### No relaying utilizing databasees:

1. vim ntlmrelayx_targets.txt
2. Put a loopback taret in format of smb://127.0.0.1

`python cyanide.py -iface <eth0> --responder -ntf ntlmrelayx_targets.txt --no-relay`
___
# LICENSING
All code except any files under horizon3_impacket maintain a GPLv3 license.  All code under horizon3_impacket maintain Impackets original license of Apache.  For more information, please see the licenses directory.
