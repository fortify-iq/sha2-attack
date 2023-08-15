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
    def round(self, state, w, rk, return_sample):
        temp1 = self.dtype(
            state[7] +
            self.s1(state[4]) +
            self.ch(state[4], state[5], state[6])
            + rk
        )
        temp2 = self.s0(state[0]) + self.maj(state[0], state[1], state[2])
        delta_a = temp1 + temp2
        delta_e = state[3] + temp1
        new_a = w + delta_a
        new_e = w + delta_e
        if return_sample:
            sample = np.uint16(
                self.hd(new_a, state[0]) +
                self.hd(state[0], state[1]) +
                self.hd(state[1], state[2]) +
                self.hd(state[2], state[3]) +
                self.hd(new_e, state[4]) +
                self.hd(state[4], state[5]) +
                self.hd(state[5], state[6]) +
                self.hd(state[6], state[7])
            )
        else:
            sample = None
        res = np.delete(state, 7, 0)
        res = np.delete(res, 3, 0)
        res = np.insert(res, 0, new_a, 0)
        res = np.insert(res, 4, new_e, 0)
        # print(f'{w + delta_a:08x} {w + delta_e:08x}')
        return res, sample, delta_a, delta_e

    def compress(self, w, iv=None, trace_size=2):
        first_block = iv is None
        if first_block:
            iv = self.iv
        if len(w.shape) == 1:
            state = iv.copy()
        else:
            state = np.transpose(np.broadcast_to(iv, (w.shape[1], 8)))
        round_count = len(self.round_const)
        trace = []
        for i in range(round_count):
            if i >= 16:
                wlast = self.sigma1(w[14]) + w[9] + self.sigma0(w[1]) + w[0]
            else:
                wlast = w[0].copy()
            w[:-1] = w[1:]
            w[-1] = wlast
            state, sample, junk, junk = self.round(
                state,
                wlast,
                self.round_const[i],
                i < trace_size
            )
            if i < trace_size:
                trace.append(sample)
        if first_block:
            state += iv
            junk, junk, delta_a, delta_e = self.round(
                state,
                0,
                self.round_const[0],
                False
            )
            return np.append(state, [delta_a, delta_e])
        return (
            np.transpose(np.broadcast_to(iv, state.shape[::-1])) + state,
            np.array(trace)
        )

    @staticmethod
    def show(data, size, total_nibble_count):
        if size == -1:
            return '.' * total_nibble_count
        nibble_count = (size >> 2) + 1
        formatter = '.' * (total_nibble_count - nibble_count) + \
                    '{{:0{}x}}'.format(nibble_count)

        return formatter.format(data)


class Sha256(Sha2):
    dtype = np.uint32
    bit_count = 32
    nibble_count = 8
    formatter = '{:08x} '
    round_const = [np.uint32(x) for x in [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
    ]]
    iv = np.array([
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ], dtype=np.uint32)
    nibbles_in_block = 128
    ipad = np.uint32(0x36363636)
    opad = np.uint32(0x5c5c5c5c)
    isize = [2, 0x40]

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
        return np.uint32(
            (a >> 2) ^
            (a << 30) ^
            (a >> 13) ^
            (a << 19) ^
            (a >> 22) ^
            (a << 10)
        )

    @staticmethod
    def s1(e):
        return np.uint32(
            (e >> 6) ^
            (e << 26) ^
            (e >> 11) ^
            (e << 21) ^
            (e >> 25) ^
            (e << 7)
        )

    @staticmethod
    def sigma0(w):
        return np.uint32(
            (w >> 7) ^
            (w << 25) ^
            (w >> 18) ^
            (w << 14) ^
            (w >> 3)
        )

    @staticmethod
    def sigma1(w):
        return np.uint32(
            (w >> 17) ^
            (w << 15) ^
            (w >> 19) ^
            (w << 13) ^
            (w >> 10)
        )


class Sha512(Sha2):
    dtype = np.uint64
    bit_count = 64
    nibble_count = 16
    formatter = '{:016x} '
    round_const = [np.uint64(x) for x in [
        0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
        0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
        0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
        0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
        0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
        0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
        0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
        0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
        0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
        0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
        0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
        0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
        0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
        0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
    ]]
    iv = np.array([
        0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
        0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
    ], dtype=np.uint64)
    nibbles_in_block = 256
    ipad = np.uint64(0x3636363636363636)
    opad = np.uint64(0x5c5c5c5c5c5c5c5c)
    isize = [0, 0x480]

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

    @staticmethod
    def sigma0(w):
        return np.uint64(
            (w >> np.uint64(19))
            ^ (w << np.uint64(45))
            ^ (w >> np.uint64(61))
            ^ (w << np.uint64(3))
            ^ (w >> np.uint64(6))
        )

    @staticmethod
    def sigma1(w):
        return np.uint64(
            (w >> np.uint64(1))
            ^ (w << np.uint64(63))
            ^ (w >> np.uint64(8))
            ^ (w << np.uint64(56))
            ^ (w >> np.uint64(7))
        )
