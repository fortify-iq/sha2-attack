#  Copyright © 2022 FortifyIQ, Inc.
#
#  All Rights Reserved.
#
#  All information contained herein is, and remains, the property of FortifyIQ, Inc.
#  Dissemination of this information or reproduction of this material, in any medium,
#  is strictly forbidden unless prior written permission is obtained from FortifyIQ, Inc.

import numpy as np


def generate_traces(sha, trace_count, seed, noise):
    state = np.random.RandomState(seed)
    iv = list(state.randint(1 << sha.bit_count, size=8, dtype=sha.dtype))
    data = state.randint(1 << sha.bit_count, size=(trace_count, 2), dtype=sha.dtype)

    temp1_0 = iv[7] + sha.s1(iv[4]) + sha.ch(iv[4], iv[5], iv[6]) + sha.round_const[0]
    temp2_0 = sha.s0(iv[0]) + sha.maj(iv[0], iv[1], iv[2])
    delta_a = temp1_0 + temp2_0
    delta_e = iv[3] + temp1_0
    hd1c = (
        sha.hd(iv[0], iv[1]) + sha.hd(iv[1], iv[2]) + sha.hd(iv[4], iv[5]) + sha.hd(iv[5], iv[6])
    )
    hd0c = hd1c + sha.hd(iv[2], iv[3]) + sha.hd(iv[6], iv[7])
    a1 = data[:, 0] + delta_a
    e1 = data[:, 0] + delta_e
    hd0v = sha.hd(a1, iv[0]) + sha.hd(e1, iv[4])

    temp1_1 = iv[6] + sha.s1(e1) + sha.ch(e1, iv[4], iv[5]) + sha.round_const[1]
    temp2_1 = sha.s0(a1) + sha.maj(a1, iv[0], iv[1])
    a2 = data[:, 1] + temp1_1 + temp2_1
    e2 = data[:, 1] + iv[2] + temp1_1
    hd1v = hd0v + sha.hd(a2, a1) + sha.hd(e2, e1)

    traces = np.array([hd0c + hd0v, hd1c + hd1v]).transpose()
    if noise:
        traces = traces.astype(float)
        traces += np.random.normal(scale=noise, size=(trace_count, 2))

    return data, traces, iv + [delta_a, delta_e]
