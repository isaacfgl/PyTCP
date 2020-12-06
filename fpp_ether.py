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
# fpp_ethernet.py - packet parser for Ethernet protocol
#


import struct

import config

# Ethernet packet header

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +    Destination MAC Address    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# >                               |                               >
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+      Source MAC Address       +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           EtherType           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


ETHER_HEADER_LEN = 14

ETHER_TYPE_MIN = 0x0600
ETHER_TYPE_ARP = 0x0806
ETHER_TYPE_IP4 = 0x0800
ETHER_TYPE_IP6 = 0x86DD


ETHER_TYPE_TABLE = {ETHER_TYPE_ARP: "ARP", ETHER_TYPE_IP4: "IPv4", ETHER_TYPE_IP6: "IPv6"}


class EtherPacket:
    """ Ethernet packet support class """

    def __init__(self, raw_packet, hptr):
        """ Class constructor """

        self.sanity_check_failed = self.__pre_parse_sanity_check(raw_packet, hptr)
        if self.sanity_check_failed:
            return

        self.dst = ":".join([f"{_:0>2x}" for _ in raw_packet[hptr + 0 : hptr + 6]])
        self.src = ":".join([f"{_:0>2x}" for _ in raw_packet[hptr + 6 : hptr + 12]])
        self.type = struct.unpack("!H", raw_packet[hptr + 12 : hptr + 14])[0]

        self.hptr = hptr
        self.dptr = hptr + 14

        self.sanity_check_failed = self.__post_parse_sanity_check()

    def __str__(self):
        """ Short packet log string """

        return f"ETHER {self.src} > {self.dst}, 0x{self.type:0>4x} ({ETHER_TYPE_TABLE.get(self.type, '???')})"

    def __pre_parse_sanity_check(self, raw_packet, hptr):
        """ Preliminary sanity check to be run on raw Ethernet packet prior to packet parsing """

        if not config.pre_parse_sanity_check:
            return False

        if len(raw_packet) - hptr < 14:
            return "Ethernet sanity check fail - wrong packet length (I)"

        return False

    def __post_parse_sanity_check(self):
        """ Sanity check to be run on parsed Ethernet packet """

        if not config.post_parse_sanity_check:
            return False

        if self.type < ETHER_TYPE_MIN:
            return "Ethernet sanity check fail - value of ether_type < 0x0600"

        return False
