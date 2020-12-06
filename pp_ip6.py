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
# pp_ip6.py - packet parser IPv6 protocol
#


import struct

import config
from ipv6_address import IPv6Address

# IPv6 protocol header

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Version| Traffic Class |           Flow Label                  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Payload Length        |  Next Header  |   Hop Limit   |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +                                                               +
# >                                                               >
# +                         Source Address                        +
# >                                                               >
# +                                                               +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +                                                               +
# >                                                               >
# +                      Destination Address                      +
# >                                                               >
# +                                                               +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


IP6_HEADER_LEN = 40

IP6_NEXT_HEADER_TCP = 6
IP6_NEXT_HEADER_UDP = 17
IP6_NEXT_HEADER_ICMP6 = 58

IP6_NEXT_HEADER_TABLE = {IP6_NEXT_HEADER_TCP: "TCP", IP6_NEXT_HEADER_UDP: "UDP", IP6_NEXT_HEADER_ICMP6: "ICMPv6"}

DSCP_CS0 = 0b000000
DSCP_CS1 = 0b001000
DSCP_AF11 = 0b001010
DSCP_AF12 = 0b001100
DSCP_AF13 = 0b001110
DSCP_CS2 = 0b010000
DSCP_AF21 = 0b010010
DSCP_AF22 = 0b010100
DSCP_AF23 = 0b010110
DSCP_CS3 = 0b011000
DSCP_AF31 = 0b011010
DSCP_AF32 = 0b011100
DSCP_AF33 = 0b011110
DSCP_CS4 = 0b100000
DSCP_AF41 = 0b100010
DSCP_AF42 = 0b100100
DSCP_AF43 = 0b100110
DSCP_CS5 = 0b101000
DSCP_EF = 0b101110
DSCP_CS6 = 0b110000
DSCP_CS7 = 0b111000

DSCP_TABLE = {
    DSCP_CS0: "CS0",
    DSCP_CS1: "CS1",
    DSCP_AF11: "AF11",
    DSCP_AF12: "AF12",
    DSCP_AF13: "AF13",
    DSCP_CS2: "CS2",
    DSCP_AF21: "AF21",
    DSCP_AF22: "AF22",
    DSCP_AF23: "AF23",
    DSCP_CS3: "CS3",
    DSCP_AF31: "AF31",
    DSCP_AF32: "AF32",
    DSCP_AF33: "AF33",
    DSCP_CS4: "CS4",
    DSCP_AF41: "AF41",
    DSCP_AF42: "AF42",
    DSCP_AF43: "AF43",
    DSCP_CS5: "CS5",
    DSCP_EF: "EF",
    DSCP_CS6: "CS6",
    DSCP_CS7: "CS7",
}

ECN_TABLE = {0b00: "Non-ECT", 0b10: "ECT(0)", 0b01: "ECT(1)", 0b11: "CE"}


class Ip6Packet:
    """ IPv6 packet support class """

    protocol = "IPv6"

    def __init__(self, raw_packet, hptr):
        """ Class constructor """

        self.sanity_check_failed = self.__pre_parse_sanity_check(raw_packet, hptr)
        if self.sanity_check_failed:
            return

        self.ver = raw_packet[hptr + 0] >> 4
        self.dscp = ((raw_packet[hptr + 0] & 0b00001111) << 2) | ((raw_packet[hptr + 1] & 0b11000000) >> 6)
        self.ecn = (raw_packet[hptr + 1] & 0b00110000) >> 4
        self.flow = ((raw_packet[hptr + 1] & 0b00001111) << 16) | (raw_packet[hptr + 2] << 8) | raw_packet[hptr + 3]
        self.dlen = struct.unpack("!H", raw_packet[hptr + 4 : hptr + 6])[0]
        self.next = raw_packet[hptr + 6]
        self.hop = raw_packet[hptr + 7]
        self.src = IPv6Address(raw_packet[hptr + 8 : hptr + 24])
        self.dst = IPv6Address(raw_packet[hptr + 24 : hptr + 40])

        self.hptr = hptr
        self.dptr = hptr + IP6_HEADER_LEN

        self.sanity_check_failed = self.__post_parse_sanity_check()

    def __str__(self):
        """ Short packet log string """

        return (
            f"IPv6 {self.src} > {self.dst}, next {self.next} ({IP6_NEXT_HEADER_TABLE.get(self.next, '???')}), flow {self.flow}"
            + f", dlen {self.dlen}, hop {self.hop}"
        )

    @property
    def pseudo_header(self):
        """ Returns IPv6 pseudo header that is used by TCP to compute its checksum """

        # *** in the UDP/TCP length field need to account for IPv6 optional headers, current implementation assumes TCP/UDP is put right after IPv6 header ***
        return struct.pack("! 16s 16s L BBBB", self.src.packed, self.dst.packed, self.dlen, 0, 0, 0, self.next)

    def __pre_parse_sanity_check(self, raw_packet, hptr):
        """ Preliminary sanity check to be run on raw IPv6 packet prior to packet parsing """

        if not config.pre_parse_sanity_check:
            return False

        if len(raw_packet) - hptr < 40:
            return "IPv6 sanity check fail - wrong packet length (I)"

        if struct.unpack("!H", raw_packet[hptr + 4 : hptr + 6])[0] != len(raw_packet) - hptr - 40:
            return "IPv6 sanity check fail - wrong packet length (II)"

        return False

    def __post_parse_sanity_check(self):
        """ Sanity check to be run on parsed IPv6 packet """

        if not config.post_parse_sanity_check:
            return False

        # ip6_ver not set to 6
        if not self.ver == 6:
            return "IP sanity check fail - value of ip6_ver is not 6"

        # ip6_hop set to 0
        if self.hop == 0:
            return "IP sanity check fail - value of ip6_hop is 0"

        # ip6_src address is multicast
        if self.src.is_multicast:
            return "IP sanity check fail - ip6_src address is multicast"

        return False
