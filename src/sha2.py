# Copyright © 2022-present FortifyIQ, Inc. All rights reserved. 
#
# This program, sha2-attack, is free software: you can redistribute it and/or modify
# it under the terms and conditions of FortifyIQ’s free use license (”License”)
# which is located at
# https://raw.githubusercontent.com/fortify-iq/sha2-attack/master/LICENSE.
# This license governs use of the accompanying software. If you use the
# software, you accept this license. If you do not accept the license, do not
# use the software.
#
# The License permits non-commercial use, but does not permit commercial use or
# resale. This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY OR RIGHT TO ECONOMIC DAMAGES; without even the implied
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
#
# If you have any questions regarding the software of the license, please
# contact kreimer@fortifyiq.com

import numpy as np


class Sha2:
    @staticmethod
    def show(data, size, total_nibble_count):
        if size == -1:
            return '.' * total_nibble_count
        nibble_count = (size >> 2) + 1
        formatter = '.' * (total_nibble_count - nibble_count) + '{{:0{}x}}'.format(nibble_count)

        return formatter.format(data)


class Sha256:
    dtype = np.uint32
    bit_count = 32
    nibble_count = 8
    formatter = '{:08x} '
    round_const = (np.uint32(0x428a2f98), np.uint32(0x71374491))

    @staticmethod
    def show(data, size):
        return Sha2.show(data, size, Sha256.nibble_count)

    @staticmethod
    def hd(x, y):
        m1 = 0x55555555
        m2 = 0x33333333
        m4 = 0x0f0f0f0f
        h01 = 0x01010101
        t = x ^ y
        t -= (t >> 1) & m1
        t = (t & m2) + ((t >> 2) & m2)
        t = (t + (t >> 4)) & m4

        return ((t * h01) >> 24) & 0x3f

    @staticmethod
    def maj(a, b, c):
        return np.uint32((a & b) ^ (a & c) ^ (b & c))

    @staticmethod
    def ch(e, f, g):
        return np.uint32((e & f) ^ ((~e) & g))

    @staticmethod
    def s0(a):
        return np.uint32((a >> 2) ^ (a << 30) ^ (a >> 13) ^ (a << 19) ^ (a >> 22) ^ (a << 10))

    @staticmethod
    def s1(e):
        return np.uint32((e >> 6) ^ (e << 26) ^ (e >> 11) ^ (e << 21) ^ (e >> 25) ^ (e << 7))


class Sha512:
    dtype = np.uint64
    bit_count = 64
    nibble_count = 16
    formatter = '{:016x} '
    round_const = (np.uint64(0x428a2f98d728ae22), np.uint64(0x7137449123ef65cd))

    @staticmethod
    def show(data, size):
        return Sha2.show(data, size, Sha512.nibble_count)

    @staticmethod
    def hd(x, y):
        m1 = np.uint64(0x5555555555555555)
        m2 = np.uint64(0x3333333333333333)
        m4 = np.uint64(0x0f0f0f0f0f0f0f0f)
        h01 = np.uint64(0x0101010101010101)
        t = x ^ y
        t -= (t >> np.uint64(1)) & m1
        t = (t & m2) + ((t >> np.uint64(2)) & m2)
        t = (t + (t >> np.uint64(4))) & m4

        return ((t * h01) >> np.uint64(56)) & np.uint64(0x7f)

    @staticmethod
    def maj(a, b, c):
        return np.uint64((a & b) ^ (a & c) ^ (b & c))

    @staticmethod
    def ch(e, f, g):
        return np.uint64((e & f) ^ ((~e) & g))

    @staticmethod
    def s0(a):
        return np.uint64(
            (a >> np.uint64(28))
            ^ (a << np.uint64(36))
            ^ (a >> np.uint64(34))
            ^ (a << np.uint64(30))
            ^ (a >> np.uint64(39))
            ^ (a << np.uint64(25))
        )

    @staticmethod
    def s1(e):
        return np.uint64(
            (e >> np.uint64(14))
            ^ (e << np.uint64(50))
            ^ (e >> np.uint64(18))
            ^ (e << np.uint64(46))
            ^ (e >> np.uint64(41))
            ^ (e << np.uint64(23))
        )
