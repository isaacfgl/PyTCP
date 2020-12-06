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
# fpp_icmp4.py - packet parser for ICMPv4 protocol
#


import struct

import config
from ip_helper import inet_cksum

# Echo reply message (0/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Destination Unreachable message (3/[0-3, 5-15])

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Reserved                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Destination Unreachable message (3/4)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           Reserved            |          Link MTU / 0         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Echo Request message (8/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


ICMP4_ECHOREPLY = 0
ICMP4_UNREACHABLE = 3
ICMP4_UNREACHABLE__NET = 0
ICMP4_UNREACHABLE__HOST = 1
ICMP4_UNREACHABLE__PROTOCOL = 2
ICMP4_UNREACHABLE__PORT = 3
ICMP4_UNREACHABLE__FAGMENTATION = 4
ICMP4_UNREACHABLE__SOURCE_ROUTE_FAILED = 5
ICMP4_ECHOREQUEST = 8


class Icmp4Packet:
    """ ICMPv4 packet support class """

    def __init__(self, raw_packet, hptr):
        """ Class constructor """

        self.sanity_check_failed = self.__pre_parse_sanity_check(raw_packet, hptr)
        if self.sanity_check_failed:
            return

        self.type = raw_packet[hptr + 0]
        self.code = raw_packet[hptr + 1]
        self.cksum = struct.unpack("!H", raw_packet[hptr + 2 : hptr + 4])[0]

        if self.type == ICMP4_ECHOREPLY:
            self.ec_id = struct.unpack("!H", raw_packet[hptr + 4 : hptr + 6])[0]
            self.ec_seq = struct.unpack("!H", raw_packet[hptr + 6 : hptr + 8])[0]
            self.ec_data = raw_packet[hptr + 8 :]

        elif self.type == ICMP4_UNREACHABLE:
            self.un_reserved = struct.unpack("!L", raw_packet[hptr + 4 : hptr + 6])[0]
            self.un_data = raw_packet[hptr + 8 :]

        elif self.type == ICMP4_ECHOREQUEST:
            self.ec_id = struct.unpack("!H", raw_packet[hptr + 4 : hptr + 6])[0]
            self.ec_seq = struct.unpack("!H", raw_packet[hptr + 6 : hptr + 8])[0]
            self.ec_data = raw_packet[hptr + 8 :]

        self.sanity_check_failed = self.__post_parse_sanity_check()

        self.hptr = hptr

    def __str__(self):
        """ Short packet log string """

        log = f"ICMPv4 type {self.type}, code {self.code}"

        if self.type == ICMP4_ECHOREPLY:
            log += f", id {self.ec_id}, seq {self.ec_seq}"

        elif self.type == ICMP4_UNREACHABLE and self.code == ICMP4_UNREACHABLE__PORT:
            pass

        elif self.type == ICMP4_ECHOREQUEST:
            log += f", id {self.ec_id}, seq {self.ec_seq}"

        return log

    @property
    def raw_packet(self):
        """ Get packet in raw format """

        if self.type == ICMP4_ECHOREPLY:
            raw_packet = struct.pack("! BBH HH", self.type, self.code, self.cksum, self.ec_id, self.ec_seq) + self.ec_data

        elif self.type == ICMP4_UNREACHABLE and self.code == ICMP4_UNREACHABLE__PORT:
            raw_packet = struct.pack("! BBH L", self.type, self.code, self.cksum, self.un_reserved) + self.un_data

        elif self.type == ICMP4_ECHOREQUEST:
            raw_packet = struct.pack("! BBH HH", self.type, self.code, self.cksum, self.ec_id, self.ec_seq) + self.ec_data

        else:
            raw_packet = struct.pack("! BBH", self.type, self.code, self.cksum) + self.unknown_message

        return raw_packet

    def __pre_parse_sanity_check(self, raw_packet, hptr):
        """ Preliminary sanity check to be run on raw ICMPv4 packet prior to packet parsing """

        if not config.pre_parse_sanity_check:
            return False

        if inet_cksum(raw_packet[hptr:]):
            return "ICMPv4 sanity check fail - wrong packet checksum"

        if len(raw_packet) - hptr < 4:
            return "ICMPv4 sanity check fail - wrong packet length (I)"

        if raw_packet[hptr + 0] == ICMP4_ECHOREPLY:
            if len(raw_packet) - hptr < 8:
                return "ICMPv6 sanity check fail - wrong packet length (II)"

        elif raw_packet[hptr + 0] == ICMP4_UNREACHABLE:
            if len(raw_packet) - hptr < 12:
                return "ICMPv6 sanity check fail - wrong packet length (II)"

        elif raw_packet[hptr + 0] == ICMP4_ECHOREQUEST:
            if len(raw_packet) - hptr < 8:
                return "ICMPv6 sanity check fail - wrong packet length (II)"

        return False

    def __post_parse_sanity_check(self):
        """ Sanity check to be run on parsed ICMPv6 packet """

        if not config.post_parse_sanity_check:
            return False

        if self.type == ICMP4_ECHOREPLY:
            # imcp4_code SHOULD be set to 0 (RFC 792)
            if not self.code == 0:
                return "ICMPv4 sanity check warning - imcp4_code SHOULD be set to 0 (RFC 792)"

        if self.type == ICMP4_UNREACHABLE:
            # imcp4_code MUST be set to [0-15] (RFC 792)
            if not self.code in {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}:
                return "ICMPv4 sanity check fail - imcp4_code MUST be set to [0-15] (RFC 792)"

        elif self.type == ICMP4_ECHOREQUEST:
            # imcp4_code SHOULD be set to 0 (RFC 792)
            if not self.code == 0:
                return "ICMPv4 sanity check warning - imcp4_code SHOULD be set to 0 (RFC 792)"

        return False
