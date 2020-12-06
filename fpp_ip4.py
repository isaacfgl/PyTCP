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
# fpp_ip4.py - packet parser for IPv4 protocol
#


import struct

import config
from ip_helper import inet_cksum
from ipv4_address import IPv4Address

# IPv4 protocol header

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |Version|  IHL  |   DSCP    |ECN|          Total Length         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Identification        |Flags|      Fragment Offset    |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Time to Live |    Protocol   |         Header Checksum       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Source Address                          |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Destination Address                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                    Options                    ~    Padding    ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


IP4_HEADER_LEN = 20

IP4_PROTO_ICMP4 = 1
IP4_PROTO_TCP = 6
IP4_PROTO_UDP = 17


IP4_PROTO_TABLE = {IP4_PROTO_ICMP4: "ICMPv4", IP4_PROTO_TCP: "TCP", IP4_PROTO_UDP: "UDP"}


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


class Ip4Packet:
    """ IPv4 packet support class """

    def __init__(self, raw_packet, hptr):
        """ Class constructor """

        self.sanity_check_failed = self.__pre_parse_sanity_check(raw_packet, hptr)
        if self.sanity_check_failed:
            return

        self.ver = raw_packet[hptr + 0] >> 4
        self.hlen = (raw_packet[hptr + 0] & 0b00001111) << 2
        self.dscp = (raw_packet[hptr + 1] & 0b11111100) >> 2
        self.ecn = raw_packet[hptr + 1] & 0b00000011
        self.plen = struct.unpack("!H", raw_packet[hptr + 2 : hptr + 4])[0]
        self.packet_id = struct.unpack("!H", raw_packet[hptr + 4 : hptr + 6])[0]
        self.flag_reserved = bool(struct.unpack("!H", raw_packet[hptr + 6 : hptr + 8])[0] & 0b1000000000000000)
        self.flag_df = bool(struct.unpack("!H", raw_packet[hptr + 6 : hptr + 8])[0] & 0b0100000000000000)
        self.flag_mf = bool(struct.unpack("!H", raw_packet[hptr + 6 : hptr + 8])[0] & 0b0010000000000000)
        self.frag_offset = (struct.unpack("!H", raw_packet[hptr + 6 : hptr + 8])[0] & 0b0001111111111111) << 3
        self.ttl = raw_packet[hptr + 8]
        self.proto = raw_packet[hptr + 9]
        self.cksum = struct.unpack("!H", raw_packet[hptr + 10 : hptr + 12])[0]
        self.src = IPv4Address(raw_packet[hptr + 12 : hptr + 16])
        self.dst = IPv4Address(raw_packet[hptr + 16 : hptr + 20])

        self.options = []

        opt_cls = {}

        optr = hptr + IP4_HEADER_LEN

        while optr < hptr + self.hlen:

            if raw_packet[optr] == IP4_OPT_EOL:
                self.options.append(Ip4OptEol())
                break

            if raw_packet[optr] == IP4_OPT_NOP:
                self.options.append(Ip4OptNop())
                optr += IP4_OPT_NOP_LEN
                continue

            self.options.append(opt_cls.get(raw_packet[optr], Ip4OptUnk)(raw_packet, optr))
            optr += raw_packet[optr + 1]

        self.hptr = hptr
        self.dptr = hptr + self.hlen

        self.sanity_check_failed = self.__post_parse_sanity_check()

    def __str__(self):
        """ Short packet log string """

        return (
            f"IPv4 {self.src} > {self.dst}, proto {self.proto} ({IP4_PROTO_TABLE.get(self.proto, '???')}), id {self.packet_id}"
            + f"{', DF' if self.flag_df else ''}{', MF' if self.flag_mf else ''}, offset {self.frag_offset}, plen {self.plen}"
            + f", ttl {self.ttl}"
        )

    @property
    def pseudo_header(self):
        """ Returns IPv4 pseudo header that is used by TCP and UDP to compute their checksums """

        return struct.pack("! 4s 4s BBH", self.src.packed, self.dst.packed, 0, self.proto, self.plen - self.hlen)

    def get_option(self, name):
        """ Find specific option by its name """

        for option in self.options:
            if option.name == name:
                return option
        return None

    def __pre_parse_sanity_check(self, raw_packet, hptr):
        """ Preliminary sanity check to be run on raw IPv4 packet prior to packet parsing """

        if not config.pre_parse_sanity_check:
            return False

        if len(raw_packet) - hptr < 20:
            return "IPv4 sanity check fail - wrong packet length (I)"

        hlen = (raw_packet[hptr + 0] & 0b00001111) << 2
        plen = struct.unpack("!H", raw_packet[hptr + 2 : hptr + 4])[0]
        if not 20 <= hlen <= plen == len(raw_packet) - hptr:
            return "IPv4 sanity check fail - wrong packet length (II)"

        # Cannot compute checksum earlier because it depends on sanity of hlen field
        if inet_cksum(raw_packet[hptr : hptr + hlen]):
            return "IPv4 sanity check fail - wrong packet checksum"

        optr = hptr + 20
        while optr < hptr + hlen:
            if raw_packet[optr] == IP4_OPT_EOL:
                break
            if raw_packet[optr] == IP4_OPT_NOP:
                optr += 1
                if optr > hptr + hlen:
                    return "IPv4 sanity check fail - wrong option length (I)"
                continue
            if optr + 1 > hptr + hlen:
                return "IPv4 sanity check fail - wrong option length (II)"
            if raw_packet[optr + 1] == 0:
                return "IPv4 sanity check fail - wrong option length (III)"
            optr += raw_packet[optr + 1]
            if optr > hptr + hlen:
                return "IPv4 sanity check fail - wrong option length (IV)"

        return False

    def __post_parse_sanity_check(self):
        """ Sanity check to be run on parsed IPv4 packet """

        if not config.post_parse_sanity_check:
            return False

        # ip4_ver not set to 4
        if not self.ver == 4:
            return "IP sanity check fail - value of ip4_ver is not 4"

        # ip4_ttl set to 0
        if self.ver == 0:
            return "IP sanity check fail - value of ip4_ttl is 0"

        # ip4_src address is multicast
        if self.src.is_multicast:
            return "IP sanity check fail - ip4_src address is multicast"

        # ip4_src address is reserved
        if self.src.is_reserved:
            return "IP sanity check fail - ip4_src address is reserved"

        # ip4_src address is limited broadcast
        if self.src.is_limited_broadcast:
            return "IP sanity check fail - ip4_src address is limited broadcast"

        # DF and MF flags set simultaneously
        if self.flag_df and self.flag_mf:
            return "IP sanity check fail - DF and MF flags set simultaneously"

        # Fragment offset not zero but DF flag is set
        if self.frag_offset and self.flag_df:
            return "IP sanity check fail - value of ip4_frag_offset s not zeor but DF flag set"

        # Packet contains options
        if self.options and config.ip4_option_packet_drop:
            return "IP sanity check fail - packet contains options"

        return False


#
#   IPv4 options
#


# IPv4 option - End of Option Linst

IP4_OPT_EOL = 0
IP4_OPT_EOL_LEN = 1


class Ip4OptEol:
    """ IP option - End of Option List """

    def __init__(self):
        self.kind = IP4_OPT_EOL

    def __str__(self):
        return "eol"


# IPv4 option - No Operation (1)

IP4_OPT_NOP = 1
IP4_OPT_NOP_LEN = 1


class Ip4OptNop:
    """ IP option - No Operation """

    def __init__(self):
        self.kind = IP4_OPT_NOP

    def __str__(self):
        return "nop"


# IPv4 option not supported by this stack


class Ip4OptUnk:
    """ IP option not supported by this stack """

    def __init__(self, raw_packet, optr):
        self.kind = raw_packet[optr + 0]
        self.len = raw_packet[optr + 1]
        self.data = raw_packet[optr + 2 : optr + self.len]

    def __str__(self):
        return f"unk-{self.kind}-{self.len}"
