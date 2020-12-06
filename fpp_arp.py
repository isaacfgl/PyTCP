#!/usr/bin/env python3

############################################################################
#                                                                          #
#  PyTCP - Python TCP/IP stack                                             #
#  Copyright (C) 2020  Sebastian Majewski                                  #
#                                                                          #
#  This program is free software: you can redistribute it and/or modify    #
#  it under the terms of the GNU General Public License as published by    #
#  the Free Software Foundation, either version 3 of the License, or       #
#  (at your option) any later version.                                     #
#                                                                          #
#  This program is distributed in the hope that it will be useful,         #
#  but WITHOUT ANY WARRANTY; without even the implied warranty of          #
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the           #
#  GNU General Public License for more details.                            #
#                                                                          #
#  You should have received a copy of the GNU General Public License       #
#  along with this program.  If not, see <https://www.gnu.org/licenses/>.  #
#                                                                          #
#  Author's email: ccie18643@gmail.com                                     #
#  Github repository: https://github.com/ccie18643/PyTCP                   #
#                                                                          #
############################################################################

##############################################################################################
#                                                                                            #
#  This program is a work in progress and it changes on daily basis due to new features      #
#  being implemented, changes being made to already implemented features, bug fixes, etc.    #
#  Therefore if the current version is not working as expected try to clone it again the     #
#  next day or shoot me an email describing the problem. Any input is appreciated. Also      #
#  keep in mind that some features may be implemented only partially (as needed for stack    #
#  operation) or they may be implemented in sub-optimal or not 100% RFC compliant way (due   #
#  to lack of time) or last but not least they may contain bug(s) that i didn't notice yet.  #
#                                                                                            #
##############################################################################################


#
# fpp_arp.py - packet_parser for ARP protocol
#


import struct

import config
from ipv4_address import IPv4Address

# ARP packet header - IPv4 stack version only

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Hardware Type         |         Protocol Type         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Hard Length  |  Proto Length |           Operation           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +        Sender Mac Address     +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# >                               |       Sender IP Address       >
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# >                               |                               >
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+       Target MAC Address      |
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Target IP Address                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


ARP_HEADER_LEN = 28

ARP_OP_REQUEST = 1
ARP_OP_REPLY = 2


class ArpPacket:
    """ ARP packet support class """

    def __init__(self, raw_packet, hptr):
        """ Class constructor """

        self.sanity_check_failed = self.__pre_parse_sanity_check(raw_packet, hptr)
        if self.sanity_check_failed:
            return

        self.hrtype = struct.unpack("!H", raw_packet[hptr + 0 : hptr + 2])[0]
        self.prtype = struct.unpack("!H", raw_packet[hptr + 2 : hptr + 4])[0]
        self.hrlen = raw_packet[hptr + 4]
        self.prlen = raw_packet[hptr + 5]
        self.oper = struct.unpack("!H", raw_packet[hptr + 6 : hptr + 8])[0]
        self.sha = ":".join([f"{_:0>2x}" for _ in raw_packet[hptr + 8 : hptr + 14]])
        self.spa = IPv4Address(raw_packet[hptr + 14 : hptr + 18])
        self.tha = ":".join([f"{_:0>2x}" for _ in raw_packet[hptr + 18 : hptr + 24]])
        self.tpa = IPv4Address(raw_packet[hptr + 24 : hptr + 28])

        self.sanity_check_failed = self.__post_parse_sanity_check()

        self.hptr = hptr

    def __str__(self):
        """ Short packet log string """

        if self.oper == ARP_OP_REQUEST:
            return f"ARP request {self.spa} / {self.sha} > {self.tpa} / {self.tha}"
        if self.oper == ARP_OP_REPLY:
            return f"ARP reply {self.spa} / {self.sha} > {self.tpa} / {self.tha}"
        return f"ARP unknown operation {self.oper}"

    def __pre_parse_sanity_check(self, raw_packet, hptr):
        """ Preliminary sanity check to be run on raw ARP packet prior to packet parsing """

        if not config.pre_parse_sanity_check:
            return False

        if len(raw_packet) - hptr < 28:
            return "ARP sanity check fail - wrong packet length (I)"

        return False

    def __post_parse_sanity_check(self):
        """ Sanity check to be run on parsed ARP packet """

        if not config.post_parse_sanity_check:
            return False

        if not self.hrtype == 1:
            return "ARP sanity check fail - value of arp_hrtype is not 1"

        if not self.prtype == 0x0800:
            return "ARP sanity check fail - value of arp_prtype is not 0x0800"

        if not self.hrlen == 6:
            return "ARP sanity check fail - value of arp_hrlen is not 6"

        if not self.prlen == 4:
            return "ARP sanity check fail - value of arp_prlen is not 4"

        if not self.oper in {1, 2}:
            return "ARP sanity check fail - value of oper is not [1-2]"

        return False
