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
# fpp_udp.py - Fast Packet Parser class for UDP protocol
#


import struct

import config
from ip_helper import inet_cksum

# UDP packet header (RFC 768)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |          Source port          |        Destination port       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |         Packet length         |            Checksum           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


UDP_HEADER_LEN = 8


class UdpPacket:
    """ UDP packet support class """

    def __init__(self, raw_packet, hptr, pseudo_header):
        """ Class constructor """

        self.sanity_check_failed = self.__pre_parse_sanity_check(raw_packet, hptr, pseudo_header)
        if self.sanity_check_failed:
            return

        self.sport = struct.unpack("!H", raw_packet[hptr + 0 : hptr + 2])[0]
        self.dport = struct.unpack("!H", raw_packet[hptr + 2 : hptr + 4])[0]
        self.plen = struct.unpack("!H", raw_packet[hptr + 4 : hptr + 6])[0]
        self.cksum = struct.unpack("!H", raw_packet[hptr + 6 : hptr + 8])[0]
        self.data = raw_packet[hptr + UDP_HEADER_LEN :]

        self.hptr = hptr
        self.dptr = hptr + UDP_HEADER_LEN

        self.sanity_check_failed = self.__post_parse_sanity_check()

    def __str__(self):
        """ Short packet log string """

        return f"UDP {self.sport} > {self.dport}, len {self.plen}"

    def __packet_integrity_check(self, pseudo_header):
        """ Packet integrity check to be run on raw packet prior to parsing to make sure parsing is safe """

        if not config.packet_integrity_check:
            return False

        if inet_cksum(pseudo_header + raw_packet[hptr:]):
            return "UDP sanity - wrong packet checksum"

        if len(raw_packet) < 8:
            return "UDP sanity - wrong packet length (I)"

        plen = struct.unpack("!H", raw_packet[hptr + 4 : hptr + 6])[0]
        if not 8 <= plen == len(raw_packet) - hptr:
            return "UDP sanity - wrong packet length (II)"

        return False

    def __post_parse_sanity_check(self):
        """ Packet sanity check to be run on parsed packet to make sure packet's fields contain sane values """

        if not config.packet_sanity_check:
            return False

        # udp_sport set to zero
        if self.sport == 0:
            return "TCP sanity fail - value of udp_sport is 0"

        # udp_dport set to zero
        if self.dport == 0:
            return "TCP sanity fail - value of udp_dport is 0"

        return False
