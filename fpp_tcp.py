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
# fpp_tcp.py - packet parser for TCP protocol
#


import struct

import config
from ip_helper import inet_cksum

# TCP packet header (RFC 793)

# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |          Source Port          |       Destination Port        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                        Sequence Number                        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |                    Acknowledgment Number                      |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |  Hlen | Res |N|C|E|U|A|P|R|S|F|            Window             |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# |           Checksum            |         Urgent Pointer        |
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
# ~                    Options                    ~    Padding    ~
# +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


TCP_HEADER_LEN = 20


class TcpPacket:
    """ TCP packet support class """

    def __init__(self, raw_packet, hptr, pseudo_header):
        """ Class constructor """

        self.sanity_check_failed = self.__pre_parse_sanity_check(raw_packet, hptr, pseudo_header)
        if self.sanity_check_failed:
            return

        self.sport = struct.unpack("!H", raw_packet[hptr + 0 : hptr + 2])[0]
        self.dport = struct.unpack("!H", raw_packet[hptr + 2 : hptr + 4])[0]
        self.seq = struct.unpack("!L", raw_packet[hptr + 4 : hptr + 8])[0]
        self.ack = struct.unpack("!L", raw_packet[hptr + 8 : hptr + 12])[0]
        self.hlen = (raw_packet[hptr + 12] & 0b11110000) >> 2
        self.reserved = raw_packet[hptr + 12] & 0b00001110
        self.flag_ns = bool(raw_packet[hptr + 12] & 0b00000001)
        self.flag_crw = bool(raw_packet[hptr + 13] & 0b10000000)
        self.flag_ece = bool(raw_packet[hptr + 13] & 0b01000000)
        self.flag_urg = bool(raw_packet[hptr + 13] & 0b00100000)
        self.flag_ack = bool(raw_packet[hptr + 13] & 0b00010000)
        self.flag_psh = bool(raw_packet[hptr + 13] & 0b00001000)
        self.flag_rst = bool(raw_packet[hptr + 13] & 0b00000100)
        self.flag_syn = bool(raw_packet[hptr + 13] & 0b00000010)
        self.flag_fin = bool(raw_packet[hptr + 13] & 0b00000001)
        self.win = struct.unpack("!H", raw_packet[hptr + 14 : hptr + 16])[0]
        self.cksum = struct.unpack("!H", raw_packet[hptr + 16 : hptr + 18])[0]
        self.urp = struct.unpack("!H", raw_packet[hptr + 18 : hptr + 20])[0]

        self.options = []

        opt_cls = {
            TCP_OPT_MSS: TcpOptMss,
            TCP_OPT_WSCALE: TcpOptWscale,
            TCP_OPT_SACKPERM: TcpOptSackPerm,
            TCP_OPT_TIMESTAMP: TcpOptTimestamp,
        }

        optr = hptr + TCP_HEADER_LEN

        while optr < hptr + self.hlen:

            if raw_packet[optr] == TCP_OPT_EOL:
                self.options.append(TcpOptEol())
                break

            if raw_packet[optr] == TCP_OPT_NOP:
                self.options.append(TcpOptNop())
                optr += TCP_OPT_NOP_LEN
                continue

            self.options.append(opt_cls.get(raw_packet[optr], TcpOptUnk)(raw_packet, optr))
            optr += raw_packet[optr + 1]

        self.data = raw_packet[hptr + self.hlen :]

        self.hptr = hptr
        self.optr = hptr + TCP_HEADER_LEN
        self.dptr = hptr + self.hlen

        self.sanity_check_failed = self.__post_parse_sanity_check()

    def __str__(self):
        """ Short packet log string """

        log = (
            f"TCP {self.sport} > {self.dport}, {'N' if self.flag_ns else ''}{'C' if self.flag_crw else ''}"
            + f"{'E' if self.flag_ece else ''}{'U' if self.flag_urg else ''}{'A' if self.flag_ack else ''}"
            + f"{'P' if self.flag_psh else ''}{'R' if self.flag_rst else ''}{'S' if self.flag_syn else ''}"
            + f"{'F' if self.flag_fin else ''}, seq {self.seq}, ack {self.ack}, win {self.win}, dlen {len(self.data)}"
        )

        for option in self.options:
            log += ", " + str(option)

        return log

    @property
    def mss(self):
        """ TCP option - Maximum Segment Size (2) """

        for option in self.options:
            if option.kind == TCP_OPT_MSS:
                return option.mss
        return 536

    @property
    def wscale(self):
        """ TCP option - Window Scale (3) """

        for option in self.options:
            if option.kind == TCP_OPT_WSCALE:
                return 1 << option.wscale
        return None

    @property
    def sackperm(self):
        """ TCP option - Sack Permit (4) """

        for option in self.options:
            if option.kind == TCP_OPT_SACKPERM:
                return True
        return None

    @property
    def timestamp(self):
        """ TCP option - Timestamp (8) """

        for option in self.options:
            if option.kind == TCP_OPT_TIMESTAMP:
                return option.tsval, option.tsecr
        return None

    def __pre_parse_sanity_check(self, raw_packet, hptr, pseudo_header):
        """ Preliminary sanity check to be run on raw TCP packet prior to packet parsing """

        if not config.pre_parse_sanity_check:
            return False

        if inet_cksum(pseudo_header + raw_packet[hptr:]):
            return "TCP sanity check fail - wrong packet checksum"

        if len(raw_packet) - hptr < 20:
            return "TCP sanity check fail - wrong packet length (I)"

        hlen = (raw_packet[hptr + 12] & 0b11110000) >> 2
        if not 20 <= hlen <= len(raw_packet) - hptr:
            return "TCP sanity check fail - wrong packet length (II)"

        optr = hptr + 20
        while optr < hptr + hlen:
            if raw_packet[optr] == TCP_OPT_EOL:
                break
            if raw_packet[optr] == TCP_OPT_NOP:
                optr += 1
                if optr > hptr + hlen:
                    return "TCP sanity check fail - wrong option length (I)"
                continue
            if optr + 1 > hptr + hlen:
                return "TCP sanity check fail - wrong option length (II)"
            if raw_packet[optr + 1] == 0:
                return "TCP sanity check fail - wrong option length (III)"
            optr += raw_packet[optr + 1]
            if optr > hptr + hlen:
                return "TCP sanity check fail - wrong option length (IV)"

        return False

    def __post_parse_sanity_check(self):
        """ Sanity check to be run on parsed TCP packet """

        if not config.post_parse_sanity_check:
            return False

        # tcp_sport set to zero
        if self.sport == 0:
            return "TCP sanity check fail - value of tcp_sport is 0"

        # tcp_dport set to zero
        if self.dport == 0:
            return "TCP sanity check fail - value of tcp_dport is 0"

        # SYN and FIN flag cannot be set simultaneously
        if self.flag_syn and self.flag_fin:
            return "TCP sanity check fail - SYN and FIN flags are set simultaneously"

        # SYN and RST flag cannot be set simultaneously
        if self.flag_syn and self.flag_rst:
            return "TCP sanity check fail - SYN and RST flags are set simultaneously"

        # FIN and RST flag cannot be set simultaneously
        if self.flag_fin and self.flag_rst:
            return "TCP sanity check fail - FIN and RST flags are set simultaneously"

        # FIN flag must be set together with ACK flag
        if self.flag_fin and not self.flag_ack:
            return "TCP sanity check fail - FIN set but ACK flag is not set"

        # ACK number set to non zero value but the ACK flag is not set
        if self.ack and not self.flag_ack:
            return "TCP sanity check fail - ACK number present but ACK flag is not set"

        # URG pointer set to non zero value but the URG flag is not set
        if self.urp and not self.flag_urg:
            return "TCP sanity check fail - URG pointer present but URG flag is not set"

        return False


#
# TCP options
#


# TCP option - End of Option List (0)

TCP_OPT_EOL = 0
TCP_OPT_EOL_LEN = 1


class TcpOptEol:
    """ TCP option - End of Option List (0) """

    def __init__(self):
        self.kind = TCP_OPT_EOL

    def __str__(self):
        return "eol"


# TCP option - No Operation (1)

TCP_OPT_NOP = 1
TCP_OPT_NOP_LEN = 1


class TcpOptNop:
    """ TCP option - No Operation (1) """

    def __init__(self):
        self.kind = TCP_OPT_NOP

    def __str__(self):
        return "nop"


# TCP option - Maximum Segment Size (2)

TCP_OPT_MSS = 2
TCP_OPT_MSS_LEN = 4


class TcpOptMss:
    """ TCP option - Maximum Segment Size (2) """

    def __init__(self, raw_packet, optr):
        self.kind = raw_packet[optr + 0]
        self.len = raw_packet[optr + 1]
        self.mss = struct.unpack("!H", raw_packet[optr + 2 : optr + 4])[0]

    def __str__(self):
        return f"mss {self.mss}"


# TCP option - Window Scale (3)

TCP_OPT_WSCALE = 3
TCP_OPT_WSCALE_LEN = 3


class TcpOptWscale:
    """ TCP option - Window Scale (3) """

    def __init__(self, raw_packet, optr):
        self.kind = raw_packet[optr + 0]
        self.len = raw_packet[optr + 1]
        self.wscale = raw_packet[optr + 2]

    def __str__(self):
        return f"wscale {self.wscale}"


# TCP option - Sack Permit (4)

TCP_OPT_SACKPERM = 4
TCP_OPT_SACKPERM_LEN = 2


class TcpOptSackPerm:
    """ TCP option - Sack Permit (4) """

    def __init__(self, raw_packet, optr):
        self.kind = raw_packet[optr + 0]
        self.len = raw_packet[optr + 1]

    def __str__(self):
        return "sack_perm"


# TCP option - Timestamp

TCP_OPT_TIMESTAMP = 8
TCP_OPT_TIMESTAMP_LEN = 10


class TcpOptTimestamp:
    """ TCP option - Timestamp (8) """

    def __init__(self, raw_packet, optr):
        self.kind = raw_packet[optr + 0]
        self.len = raw_packet[optr + 1]
        self.tsval = struct.unpack("!L", raw_packet[optr + 2 : optr + 6])[0]
        self.tsecr = struct.unpack("!L", raw_packet[optr + 6 : optr + 10])[0]

    def __str__(self):
        return f"ts {self.tsval}/{self.tsecr}"


# TCP option not supported by this stack


class TcpOptUnk:
    """ TCP option not supported by this stack """

    def __init__(self, raw_packet, optr):
        self.kind = raw_packet[optr + 0]
        self.len = raw_packet[optr + 1]
        self.data = raw_packet[optr + 2 : optr + self.len]

    def __str__(self):
        return f"unk-{self.kind}-{self.len}"
