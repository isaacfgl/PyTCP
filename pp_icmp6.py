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
# pp_icmp6.py - packet parser for ICMPv6 protocol
#


import struct

import config
from ip_helper import inet_cksum
from ipv6_address import IPv6Address, IPv6Network
from tracker import Tracker

# Destination Unreachable message (1/[0-6])

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Reserved                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Packet Too Big message (2/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                             MTU                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Time Exceeded (3/[0-1])

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                            Unused                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# Parameter Problem message (4/[0-2])

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Pointer                             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# Echo Request message (128/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Echo Reply message (129/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |              Id               |              Seq              |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                             Data                              ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# MLDv2 - Multicast Listener Query message (130/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |      Type     |      Code     |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |    Maximum Response Code      |           Reserved            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               *
# |                                                               |
# +                       Multicast Address                       *
# |                                                               |
# +                                                               *
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# | Resv  |S| QRV |     QQIC      |     Number of Sources (N)     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Source Address [1]                      +
# |                                                               |
# +                                                               +
# |                                                               |
# +---------------------------------------------------------------+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Source Address [2]                      +
# |                                                               |
# +                                                               +
# |                                                               |
# +---------------------------------------------------------------+
# .                               .                               .
# .                               .                               .
# .                               .                               .
# +---------------------------------------------------------------+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Source Address [N]                      +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


# Router Solicitation message (133/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                            Reserved                           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Options ...
# +-+-+-+-+-+-+-+-+-+-+-+-


# Router Advertisement message (134/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Hop Limit   |M|O|H|PRF|P|0|0|        Router Lifetime        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                          Reachable Time                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Retrans Timer                       |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Options ...
# +-+-+-+-+-+-+-+-+-+-+-+-


# Neighbor Solicitation message (135/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Reserved                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +                                                               +
# >                                                               >
# +                       Target Address                          +
# >                                                               >
# +                                                               +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Options ...
# +-+-+-+-+-+-+-+-+-+-+-+-


# Neighbor Advertisement message (136/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Code      |          Checksum             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |R|S|O|                     Reserved                            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               >
# +                                                               +
# >                                                               >
# +                       Target Address                          +
# >                                                               >
# +                                                               +
# >                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |   Options ...
# +-+-+-+-+-+-+-+-+-+-+-+-


# MLDv2 - Multicast Listener Report message (143/0)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |      Type     |      Code     |           Checksum            |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           Reserved            |Nr of Mcast Address Records (M)|
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                  Multicast Address Record [1]                 ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                  Multicast Address Record [2]                 ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# .                               .                               .
# .                               .                               .
# .                               .                               .
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                  Multicast Address Record [M]                 ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

# Each Multicast Address Record has the following internal format:

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Record Type  |  Aux Data Len |     Number of Sources (N)     |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Multicast Address                       +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Source Address [1]                      +
# |                                                               |
# +                                                               +
# |                                                               |
# +---------------------------------------------------------------+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Source Address [2]                      +
# |                                                               |
# +                                                               +
# |                                                               |
# +---------------------------------------------------------------+
# .                               .                               .
# .                               .                               .
# .                               .                               .
# +---------------------------------------------------------------+
# |                                                               |
# +                                                               +
# |                                                               |
# +                       Source Address [N]                      +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                                                               ~
# ~                         Auxiliary Data                        ~
# ~                                                               ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


ICMP6_UNREACHABLE = 1
ICMP6_UNREACHABLE__NO_ROUTE = 0
ICMP6_UNREACHABLE__PROHIBITED = 1
ICMP6_UNREACHABLE__SCOPE = 2
ICMP6_UNREACHABLE__ADDRESS = 3
ICMP6_UNREACHABLE__PORT = 4
ICMP6_UNREACHABLE__FAILED_POLICY = 5
ICMP6_UNREACHABLE__REJECT_ROUTE = 6
ICMP6_PACKET_TOO_BIG = 2
ICMP6_TIME_EXCEEDED = 3
ICMP6_PARAMETER_PROBLEM = 4
ICMP6_ECHOREQUEST = 128
ICMP6_ECHOREPLY = 129
ICMP6_MLD2_QUERY = 130
ICMP6_ROUTER_SOLICITATION = 133
ICMP6_ROUTER_ADVERTISEMENT = 134
ICMP6_NEIGHBOR_SOLICITATION = 135
ICMP6_NEIGHBOR_ADVERTISEMENT = 136
ICMP6_MLD2_REPORT = 143


ICMP6_MART_MODE_IS_INCLUDE = 1
ICMP6_MART_MODE_IS_EXCLUDE = 2
ICMP6_MART_CHANGE_TO_INCLUDE = 3
ICMP6_MART_CHANGE_TO_EXCLUDE = 4
ICMP6_MART_ALLOW_NEW_SOURCES = 5
ICMP6_MART_BLOCK_OLD_SOURCES = 6


class Icmp6Packet:
    """ ICMPv6 packet support class """

    def __init__(self, raw_packet, hptr, pseudo_header, ip6_src, ip6_dst, ip6_hop):
        """ Class constructor """

        self.sanity_check_failed = self.__pre_parse_sanity_check(raw_packet, hptr, pseudo_header)
        if self.sanity_check_failed:
            return

        self.type = raw_packet[hptr + 0]
        self.code = raw_packet[hptr + 1]
        self.cksum = struct.unpack("!H", raw_packet[hptr + 2 : hptr + 4])[0]

        self.nd_options = []

        if self.type == ICMP6_UNREACHABLE:
            self.un_reserved = struct.unpack("!L", raw_packet[hptr + 4 : hptr + 8])[0]
            self.un_data = raw_packet[hptr + 8 :]

        elif self.type == ICMP6_ECHOREQUEST:
            self.ec_id = struct.unpack("!H", raw_packet[hptr + 4 : hptr + 6])[0]
            self.ec_seq = struct.unpack("!H", raw_packet[hptr + 6 : hptr + 8])[0]
            self.ec_data = raw_packet[hptr + 8 :]

        elif self.type == ICMP6_ECHOREPLY:
            self.ec_id = struct.unpack("!H", raw_packet[hptr + 4 : hptr + 6])[0]
            self.ec_seq = struct.unpack("!H", raw_packet[hptr + 6 : hptr + 8])[0]
            self.ec_data = raw_packet[hptr + 8 :]

        elif self.type == ICMP6_ROUTER_SOLICITATION:
            self.rs_reserved = struct.unpack("!L", raw_packet[hptr + 4 : hptr + 8])[0]
            self.nd_options = self.__read_nd_options(raw_packet, hptr, hptr + 12)

        elif self.type == ICMP6_ROUTER_ADVERTISEMENT:
            self.ra_hop = raw_packet[hptr + 4]
            self.ra_flag_m = bool(raw_packet[hptr + 5] & 0b10000000)
            self.ra_flag_o = bool(raw_packet[hptr + 5] & 0b01000000)
            self.ra_reserved = raw_packet[hptr + 5] & 0b00111111
            self.ra_router_lifetime = struct.unpack("!H", raw_packet[hptr + 6 : hptr + 8])[0]
            self.ra_reachable_time = struct.unpack("!L", raw_packet[hptr + 8 : hptr + 12])[0]
            self.ra_retrans_timer = struct.unpack("!L", raw_packet[hptr + 12 : hptr + 16])[0]
            self.nd_options = self.__read_nd_options(raw_packet, hptr, hptr + 16)

        elif self.type == ICMP6_NEIGHBOR_SOLICITATION:
            self.ns_reserved = struct.unpack("!L", raw_packet[hptr + 4 : hptr + 8])[0]
            self.ns_target_address = IPv6Address(raw_packet[hptr + 8 : hptr + 24])
            self.nd_options = self.__read_nd_options(raw_packet, hptr, hptr + 24)

        elif self.type == ICMP6_NEIGHBOR_ADVERTISEMENT:
            self.na_flag_r = bool(raw_packet[hptr + 4] & 0b10000000)
            self.na_flag_s = bool(raw_packet[hptr + 4] & 0b01000000)
            self.na_flag_o = bool(raw_packet[hptr + 4] & 0b00100000)
            self.na_reserved = struct.unpack("!L", raw_packet[hptr + 4 : hptr + 8])[0] & 0b00011111111111111111111111111111
            self.na_target_address = IPv6Address(raw_packet[hptr + 8 : hptr + 24])
            self.nd_options = self.__read_nd_options(raw_packet, hptr, hptr + 24)

        elif self.type == ICMP6_MLD2_REPORT:
            self.mlr2_reserved = struct.unpack("!H", raw_packet[hptr + 4 : hptr + 6])[0]
            self.mlr2_number_of_multicast_address_records = struct.unpack("!H", raw_packet[hptr + 6 : hptr + 8])[0]
            self.mlr2_multicast_address_record = []
            raw_records = raw_packet[hptr + 8 :]
            for _ in range(self.mlr2_number_of_multicast_address_records):
                record = MulticastAddressRecord(raw_records)
                raw_records = raw_records[len(record) :]
                self.mlr2_multicast_address_record.append(record)

        self.hptr = hptr

        self.sanity_check_failed = self.__post_parse_sanity_check(ip6_src, ip6_dst, ip6_hop)

    def __str__(self):
        """ Short packet log string """

        log = f"ICMPv6 type {self.type}, code {self.code}"

        if self.type == ICMP6_UNREACHABLE:
            pass

        elif self.type == ICMP6_ECHOREQUEST:
            log += f", id {self.ec_id}, seq {self.ec_seq}"

        elif self.type == ICMP6_ECHOREPLY:
            log += f", id {self.ec_id}, seq {self.ec_seq}"

        elif self.type == ICMP6_ROUTER_SOLICITATION:
            for nd_option in self.nd_options:
                log += ", " + str(nd_option)

        elif self.type == ICMP6_ROUTER_ADVERTISEMENT:
            log += f", hop {self.ra_hop}"
            log += f"flags {'M' if self.ra_flag_m else '-'}{'O' if self.ra_flag_o else '-'}"
            log += f"rlft {self.ra_router_lifetime}, reacht {self.ra_reachable_time}, retrt {self.ra_retrans_timer}"
            for nd_option in self.nd_options:
                log += ", " + str(nd_option)

        elif self.type == ICMP6_NEIGHBOR_SOLICITATION:
            log += f", target {self.ns_target_address}"
            for nd_option in self.nd_options:
                log += ", " + str(nd_option)

        elif self.type == ICMP6_NEIGHBOR_ADVERTISEMENT:
            log += f", target {self.na_target_address}"
            log += f", flags {'R' if self.na_flag_r else '-'}{'S' if self.na_flag_s else '-'}{'O' if self.na_flag_o else '-'}"
            for nd_option in self.nd_options:
                log += ", " + str(nd_option)

        elif self.type == ICMP6_MLD2_REPORT:
            pass

        return log

    @staticmethod
    def __read_nd_options(raw_packet, hptr, optr):
        """ Read options for Neighbor Discovery """

        opt_cls = {
            ICMP6_ND_OPT_SLLA: Icmp6NdOptSLLA,
            ICMP6_ND_OPT_TLLA: Icmp6NdOptTLLA,
            ICMP6_ND_OPT_PI: Icmp6NdOptPI,
        }

        nd_options = []

        while optr < len(raw_packet):
            nd_options.append(opt_cls.get(raw_packet[optr], Icmp6NdOptUnk)(raw_packet, optr))
            optr += raw_packet[optr + 1] << 3

        return nd_options

    @property
    def nd_opt_slla(self):
        """ ICMPv6 ND option - Source Link Layer Address (1) """

        for option in self.nd_options:
            if option.code == ICMP6_ND_OPT_SLLA:
                return option.slla
        return None

    @property
    def nd_opt_tlla(self):
        """ ICMPv6 ND option - Target Link Layer Address (2) """

        for option in self.nd_options:
            if option.code == ICMP6_ND_OPT_TLLA:
                return option.tlla
        return None

    @property
    def nd_opt_pi(self):
        """ ICMPv6 ND option - Prefix Info (3) - Returns list of prefixes that can be used for address autoconfiguration"""

        return [_.prefix for _ in self.nd_options if _.code == ICMP6_ND_OPT_PI and _.flag_a and _.prefix.prefixlen == 64]

    def __nd_option_pre_parse_sanity_check(self, raw_packet, hptr, optr):
        """ Check integrity of ICMPv6 ND options """

        while optr < len(raw_packet):
            if optr + 1 > len(raw_packet):
                return "ICMPv6 sanity check fail - wrong option length (I)"
            if raw_packet[optr + 1] == 0:
                return "ICMPv6 sanity check fail - wrong option length (II)"
            optr += raw_packet[optr + 1] << 3
            if optr > len(raw_packet):
                return "ICMPv6 sanity check fail - wrong option length (III)"

        return False

    def __pre_parse_sanity_check(self, raw_packet, hptr, pseudo_header):
        """ Preliminary sanity check to be run on raw ICMPv6 packet prior to packet parsing """

        if not config.pre_parse_sanity_check:
            return False

        if inet_cksum(pseudo_header + raw_packet[hptr:]):
            return "ICMPv6 sanity check fail - wrong packet checksum"

        if len(raw_packet) - hptr < 4:
            return "ICMPv6 sanity check fail - wrong packet length (I)"

        if raw_packet[0] == ICMP6_UNREACHABLE:
            if len(raw_packet) - hptr < 12:
                return "ICMPv6 sanity check fail - wrong packet length (II)"

        elif raw_packet[0] == ICMP6_ECHOREQUEST:
            if len(raw_packet) - hptr < 8:
                return "ICMPv6 sanity check fail - wrong packet length (II)"

        elif raw_packet[0] == ICMP6_ECHOREPLY:
            if len(raw_packet) - hptr < 8:
                return "ICMPv6 sanity check fail - wrong packet length (II)"

        elif raw_packet[0] == ICMP6_MLD2_QUERY:
            if len(raw_packet) - hptr < 28:
                return "ICMPv6 sanity check fail - wrong packet length (II)"
            if len(raw_packet) - hptr != 28 + struct.unpack("! H", raw_packet[hptr + 26 : hptr + 28])[0] * 16:
                return "ICMPv6 sanity check fail - wrong packet length (III)"

        elif raw_packet[0] == ICMP6_ROUTER_SOLICITATION:
            if len(raw_packet) - hptr < 8:
                return "ICMPv6 sanity check fail - wrong packet length (II)"
            if fail := self.__nd_option_pre_parse_sanity_check(raw_packet, hptr, hptr + 8):
                return fail

        elif raw_packet[0] == ICMP6_ROUTER_ADVERTISEMENT:
            if len(raw_packet) - hptr < 16:
                return "ICMPv6 sanity check fail - wrong packet length (II)"
            if fail := self.__nd_option_pre_parse_sanity_check(raw_packet, hptr, hptr + 16):
                return fail

        elif raw_packet[0] == ICMP6_NEIGHBOR_SOLICITATION:
            if len(raw_packet) - hptr < 24:
                return "ICMPv6 sanity check fail - wrong packet length (II)"
            if fail := self.__nd_option_pre_parse_sanity_check(raw_packet, hptr, hptr + 24):
                return fail

        elif raw_packet[0] == ICMP6_NEIGHBOR_ADVERTISEMENT:
            if len(raw_packet) - hptr < 24:
                return "ICMPv6 sanity check fail - wrong packet length (II)"
            if fail := self.__nd_option_pre_parse_sanity_check(raw_packet, hptr, hptr + 24):
                return fail

        elif raw_packet[0] == ICMP6_MLD2_REPORT:
            if len(raw_packet) - hptr < 8:
                return "ICMPv6 sanity check fail - wrong packet length (II)"
            optr = hptr + 8
            for _ in range(struct.unpack("! H", raw_packet[hptr + 6 : hptr + 8])[0]):
                if optr + 20 > len(raw_packet) - hptr:
                    return "ICMPv6 sanity check fail - wrong packet length (III)"
                optr += 20 + raw_packet[optr + 1] + struct.unpack("! H", raw_packet[optr + 2 : optr + 4])[0] * 16
            if optr != len(raw_packet) - hptr:
                return "ICMPv6 sanity check fail - wrong packet lenght (IV)"

        return False

    def __post_parse_sanity_check(self, ip6_src, ip6_dst, ip6_hop):
        """ Sanity check to be run on parsed ICMPv6 packet """

        if not config.post_parse_sanity_check:
            return True

        if self.type == ICMP6_UNREACHABLE:
            # imcp6_code MUST be set to [0-6] (RFC 4861)
            if not self.code in {0, 1, 2, 3, 4, 5, 6}:
                return "ICMPv6 sanity check fail - imcp6_code MUST be set to [0-6] (RFC 4861)"

        elif self.type == ICMP6_PACKET_TOO_BIG:
            # imcp6_code SHOULD be set to 0 (RFC 4861)
            if not self.code == 0:
                return "ICMPv6 sanity check warning - imcp6_code SHOULD be set to 0 (RFC 4861)"

        elif self.type == ICMP6_TIME_EXCEEDED:
            # imcp6_code MUST be set to [0-1] (RFC 4861)
            if not self.code in {0, 1}:
                return "ICMPv6 sanity check fail - imcp6_code MUST be set to [0-1] (RFC 4861)"

        elif self.type == ICMP6_PARAMETER_PROBLEM:
            # imcp6_code MUST be set to [0-2] (RFC 4861)
            if not self.code in {0, 1, 2}:
                return "ICMPv6 sanity check fail - imcp6_code MUST be set to [0-2] (RFC 4861)"

        elif self.type == ICMP6_ECHOREQUEST:
            # imcp6_code SHOULD be set to 0 (RFC 4861)
            if not self.code == 0:
                return "ICMPv6 sanity check warning - imcp6_code SHOULD be set to 0 (RFC 4861)"

        elif self.type == ICMP6_ECHOREPLY:
            # imcp6_code SHOULD be set to 0 (RFC 4861)
            if not self.code == 0:
                return "ICMPv6 sanity check warning - imcp6_code SHOULD be set to 0 (RFC 4861)"

        elif self.type == ICMP6_MLD2_QUERY:
            # imcp6_code MUST be set to 0 (RFC 3810)
            if not self.code == 0:
                return "ICMPv6 sanity check fail - imcp6_code MUST be set to 0 (RFC 3810)"
            # ip6_hop MUST be set to 1 (RFC 3810)
            if not ip6_hop == 1:
                return "ICMPv6 sanity check fail - ip6_hop MUST be set to 255 (RFC 3810)"

        elif self.type == ICMP6_ROUTER_SOLICITATION:
            # imcp6_code MUST be set to 0 (RFC 4861)
            if not self.code == 0:
                return "ICMPv6 sanity check fail - imcp6_code MUST be set to 0 (RFC 4861)"
            # ip6_hop MUST be set to 255 (RFC 4861)
            if not ip6_hop == 255:
                return "ICMPv6 sanity check fail - ip6_hop MUST be set to 255 (RFC 4861)"
            # ip6_src MUST be unicast or unspecified (RFC 4861)
            if not (ip6_src.is_unicast or ip6_src.is_unspecified):
                return "ICMPv6 sanity check fail - ip6_src MUST be unicast or unspecified (RFC 4861)"
            # ip6_dst MUST be all-routers (RFC 4861)
            if not ip6_dst == IPv6Address("ff02::2"):
                return "ICMPv6 sanity check fail - ip6_dst MUST be all-routers (RFC 4861)"
            # icmp6_rs_opt_slla MUST NOT be included if ip6_src is unspecified
            if ip6_src.is_unspecified and self.nd_opt_slla:
                return "ICMPv6 sanity check fail - icmp6_rs_opt_slla MUST NOT be included if ip6_src is unspecified (RFC 4861)"

        elif self.type == ICMP6_ROUTER_ADVERTISEMENT:
            # imcp6_code MUST be set to 0 (RFC 4861)
            if not self.code == 0:
                return "ICMPv6 sanity check fail - imcp6_code MUST be set to 0 (RFC 4861)"
            # ip6_hop MUST be set to 255 (RFC 4861)
            if not ip6_hop == 255:
                return "ICMPv6 sanity check fail - ip6_hop MUST be set to 255 (RFC 4861)"
            # ip6_src MUST be link local (RFC 4861)
            if not ip6_src.is_link_local:
                return "ICMPv6 sanity check fail - ip6_src MUST be link local (RFC 4861)"
            # ip6_dst MUST be unicast or all-nodes (RFC 4861)
            if not (ip6_dst.is_unicast or ip6_dst == IPv6Address("ff02::1")):
                return "ICMPv6 sanity check fail - ip6_dst MUST be unicast or all-nodes (RFC 4861)"

        elif self.type == ICMP6_NEIGHBOR_SOLICITATION:
            # imcp6_code MUST be set to 0 (RFC 4861)
            if not self.code == 0:
                return "ICMPv6 sanity check fail - imcp6_code MUST be set to 0 (RFC 4861)"
            # ip6_hop MUST be set to 255 (RFC 4861)
            if not ip6_hop == 255:
                return "ICMPv6 sanity check fail - ip6_hop MUST be set to 255 (RFC 4861)"
            # ip6_src MUST be unicast or unspecified (RFC 4861)
            if not (ip6_src.is_unicast or ip6_src.is_unspecified):
                return "ICMPv6 sanity check fail - ip6_src MUST be unicast or unspecified (RFC 4861)"
            # ip6_dst MUST be icmp6_ns_target_address or it's solicited-node multicast (RFC 4861)
            if not (ip6_dst == self.ns_target_address or ip6_dst == self.ns_target_address.solicited_node_multicast):
                self.logger.debug(
                    f"{self.tracker} - ICMPv6 sanity check fail - ip6_dst MUST be icmp6_ns_target_address or it's solicited-node multicast (RFC 4861)"
                )
            # icmp6_ns_target_address MUST be unicast address (RFC 4861)
            if not self.ns_target_address.is_unicast:
                return "ICMPv6 sanity check fail - icmp6_ns_target_address MUST be unicast address (RFC 4861)"
            # icmp6_rs_opt_slla MUST NOT be included if ip6_src is unspecified address
            if ip6_src.is_unspecified and not self.nd_opt_slla is None:
                return "ICMPv6 sanity check fail - icmp6_rs_opt_slla MUST NOT be included if ip6_src is unspecified address"

        elif self.type == ICMP6_NEIGHBOR_ADVERTISEMENT:
            # imcp6_code MUST be set to 0 (RFC 4861)
            if not self.code == 0:
                return "ICMPv6 sanity check fail - imcp6_code MUST be set to 0 (RFC 4861)"
            # ip6_hop MUST be set to 255 (RFC 4861)
            if not ip6_hop == 255:
                return "ICMPv6 sanity check fail - ip6_hop MUST be set to 255 (RFC 4861)"
            # ip6_src MUST be unicast address (RFC 4861)
            if not ip6_src.is_unicast:
                return "ICMPv6 sanity check fail - ip6_src MUST be unicast address (RFC 4861)"
            # if icmp6_na_flag_s is set then ip6_dst MUST be unicast or all-nodes (RFC 4861)
            if self.na_flag_s is True and not (ip6_dst.is_unicast or ip6_dst == IPv6Address("ff02::1")):
                return "ICMPv6 sanity check fail - if icmp6_na_flag_s is set then ip6_dst MUST be unicast or all-nodes (RFC 4861)"
            # if icmp6_na_flag_s is not set then ip6_dst MUST be all-nodes (RFC 4861)
            if self.na_flag_s is False and not ip6_dst == IPv6Address("ff02::1"):
                return "ICMPv6 sanity check fail - if icmp6_na_flag_s is not set then ip6_dst MUST be all-nodes (RFC 4861)"

        elif self.type == ICMP6_MLD2_REPORT:
            # imcp6_code MUST be set to 0 (RFC 3810)
            if not self.code == 0:
                return "ICMPv6 sanity check fail - imcp6_code MUST be set to 0 (RFC 3810)"
            # ip6_hop MUST be set to 1 (RFC 3810)
            if not ip6_hop == 1:
                return "ICMPv6 sanity check fail - ip6_hop MUST be set to 1 (RFC 3810)"

        return False


#
#   ICMPv6 Neighbor Discovery options
#


# ICMPv6 ND option - Source Link Layer Address (1)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Length    |                               >
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
# >                           MAC Address                         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP6_ND_OPT_SLLA = 1
ICMP6_ND_OPT_SLLA_LEN = 8


class Icmp6NdOptSLLA:
    """ ICMPv6 ND option - Source Link Layer Address (1) """

    def __init__(self, raw_packet, optr):
        self.code = raw_packet[optr + 0]
        self.len = raw_packet[optr + 1] << 3
        self.slla = ":".join([f"{_:0>2x}" for _ in raw_packet[optr + 2 : optr + 8]])

    def __str__(self):
        return f"slla {self.slla}"


# ICMPv6 ND option - Target Link Layer Address (2)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |     Length    |                               >
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+                               +
# >                           MAC Address                         |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP6_ND_OPT_TLLA = 2
ICMP6_ND_OPT_TLLA_LEN = 8


class Icmp6NdOptTLLA:
    """ ICMPv6 ND option - Target Link Layer Address (2) """

    def __init__(self, raw_packet, optr):
        self.code = raw_packet[optr + 0]
        self.len = raw_packet[optr + 1] << 3
        self.tlla = ":".join([f"{_:0>2x}" for _ in raw_packet[optr + 2 : optr + 8]])

    def __str__(self):
        return f"tlla {self.tlla}"


# ICMPv6 ND option - Prefix Information (3)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |     Type      |    Length     | Prefix Length |L|A|R|  Res1  |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                         Valid Lifetime                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                       Preferred Lifetime                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                           Reserved2                           |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                                                               |
# +                                                               +
# |                                                               |
# +                            Prefix                             +
# |                                                               |
# +                                                               +
# |                                                               |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

ICMP6_ND_OPT_PI = 3
ICMP6_ND_OPT_PI_LEN = 32


class Icmp6NdOptPI:
    """ ICMPv6 ND option - Prefix Information (3) """

    def __init__(self, raw_packet, optr):
        self.code = raw_packet[optr + 0]
        self.len = raw_packet[optr + 1] << 3
        self.flag_l = bool(raw_packet[optr + 3] & 0b10000000)
        self.flag_a = bool(raw_packet[optr + 3] & 0b01000000)
        self.flag_r = bool(raw_packet[optr + 3] & 0b00100000)
        self.reserved_1 = raw_packet[optr + 3] & 0b00011111
        self.valid_lifetime = struct.unpack("!L", raw_packet[optr + 4 : optr + 8])[0]
        self.preferred_lifetime = struct.unpack("!L", raw_packet[optr + 8 : optr + 12])[0]
        self.reserved_2 = struct.unpack("!L", raw_packet[optr + 12 : optr + 16])[0]
        self.prefix = IPv6Network((raw_packet[optr + 16 : optr + 32], raw_packet[optr + 2]))

    def __str__(self):
        return f"prefix_info {self.prefix}"


# ICMPv6 ND option not supported by this stack


class Icmp6NdOptUnk:
    """ ICMPv6 ND  option not supported by this stack """

    def __init__(self, raw_packet, optr):
        self.code = raw_packet[optr + 0]
        self.len = raw_packet[optr + 1] << 3
        self.data = raw_packet[optr + 2 : optr + self.len]

    def __str__(self):
        return f"unk-{self.code}-{self.len}"


#
#   ICMPv6 Multicast support classes
#


class MulticastAddressRecord:
    """ Multicast Address Record used by MLDv2 Report message """

    def __init__(self, raw_record=None, record_type=None, multicast_address=None, source_address=None, aux_data=b""):
        """ Class constuctor """

        # Record parsing
        if raw_record:
            self.record_type = raw_record[0]
            self.aux_data_len = raw_record[1]
            self.number_of_sources = struct.unpack("!H", raw_record[2:4])[0]
            self.multicast_address = IPv6Address(raw_record[4:20])
            self.source_address = [IPv6Address(raw_record[20 + 16 * _ : 20 + 16 * (_ + 1)]) for _ in range(self.number_of_sources)]
            self.aux_data = raw_record[20 + 16 * self.number_of_sources :]

        # Record building
        else:
            self.record_type = record_type
            self.aux_data_len = len(aux_data)
            self.multicast_address = IPv6Address(multicast_address)
            self.source_address = [] if source_address is None else source_address
            self.number_of_sources = len(self.source_address)
            self.aux_data = aux_data

    def __len__(self):
        """ Length of raw record """

        return len(self.raw_record)

    def __hash__(self):
        """ Hash of raw record """

        return hash(self.raw_record)

    def __eq__(self, other):
        """ Compare two records """

        return self.raw_record == other.raw_record

    @property
    def raw_record(self):
        """ Get record in raw format """

        return (
            struct.pack("! BBH 16s", self.record_type, self.aux_data_len, self.number_of_sources, self.multicast_address.packed)
            + b"".join([_.packed for _ in self.source_address])
            + self.aux_data
        )
