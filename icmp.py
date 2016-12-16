"""
ICMP definition
"""

import binascii
import ctypes
import struct

class ICMP(ctypes.Structure):
    """
    Represents an ICMP packet
    """

    _fields_ = [('type', ctypes.c_byte),
                ('code', ctypes.c_byte),
                ('sum', ctypes.c_ushort)]

    icmp_header_size = 4            # An ICMP header is 4 bytes

    def __init__(self, packet, layers=0):
        fields = struct.unpack("!BBH", packet[:self.icmp_header_size])
        self.type = fields[0]
        self.code = fields[1]
        self.sum = fields[2]

    def type(self):
        if self.type == 0x00:
            return 'reply'
        elif self.type == 0x03:
            return 'destination unreachable'
        elif self.type == 0x05:
            return 'redirect'
        elif self.type == 0x08:
            return 'echo'
        elif self.type == 0x09:
            return 'router advertisement'
        elif self.type == 0x0A:
            return 'router selection'
        elif self.type == 0x0B:
            return 'time exceeded'
        elif self.type == 0x0C:
            return 'parameter problem'
        elif self.type == 0x0D:
            return 'timestamp'
        elif self.type == 0x0E:
            return 'timestamp reply'
        elif self.type == 40:
            return 'photuris'
        else:
            return 'unknown'

    def __str__(self):
        packet = 'icmp %s packet' % type()
        return packet

    def __len__(self):
        return icmp_header_size
        
