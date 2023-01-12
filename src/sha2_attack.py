#  Copyright © 2022-2023 [unidentified]
#
#  All Rights Reserved.

from collections import namedtuple

import numpy as np


Stage1hypo = namedtuple('Stage1hypo', ['nextA', 'prevA', 'nextE', 'prevE'])


def fit(pair, pattern, bit_size):
    return np.all((pair >> bit_size ^ pattern) & 1 == 0) if bit_size > 0 else True


def glue(pair, pattern, bit_size):
    return pair ^ ((pattern & 2) << bit_size) if bit_size > 0 else pattern


class Stage1state:
    hd_eq = {
        (-2, 0, -2): ((3, 3),),
        (-2, 2, -2): ((1, 3), (3, 1)),
        (-2, 4, -2): ((1, 1),),
        (0, -2, 0): ((2, 3), (3, 2)),
        (0, 0, 0): ((0, 3), (1, 2), (2, 1), (3, 0)),
        (0, 2, 0): ((0, 1), (1, 0)),
        (2, -4, 2): ((2, 2),),
        (2, -2, 2): ((0, 2), (2, 0)),
        (2, 0, 2): ((0, 0),),
    }

    hd_ne = {
        (-3, 1, -1): ((3, 2),),
        (-3, 3, -1): ((1, 2),),
        (-1, -1, 1): ((2, 2), (3, 3)),
        (-1, 1, -3): ((3, 0),),
        (-1, 1, 1): ((0, 2), (1, 3)),
        (-1, 3, -3): ((1, 0),),
        (1, -3, 3): ((2, 3),),
        (1, -1, -1): ((2, 0), (3, 1)),
        (1, -1, 3): ((0, 3),),
        (1, 1, -1): ((0, 0), (1, 1)),
        (3, -3, 1): ((2, 1),),
        (3, -1, 1): ((0, 1),),
    }

    def __init__(self, sha2, data, traces, verbose):
        self.sha2 = sha2
        self.known_bits = 0

        # DeltaA_0, DeltaE_0 (in the descending order of value)
        self.nexts = np.zeros(2, dtype=sha2.dtype)

        # A_{-1}, E{-1} (set of pairs. The order in each pair is
        # consistent with the order of self.nexts)
        self.prevs = np.zeros((1, 2), dtype=sha2.dtype)

        # For every step, call self.find_bit_before_mismatch
        # until the first mismatch between DeltaA_0 and DeltaE_0
        self.find_bit = self.find_bit_before_mismatch
        self.data = data
        self.traces = traces
        self.verbose = verbose

    def update_prevs(self, current_index, hd):
        """Substage 1b (section 3.4.2) up to the least significant mismatching
        bit between DeltaA_0 and DeltaE_0 (case 1 in section 3.4.1)"""

        mask = self.sha2.dtype((1 << (current_index + 2)) - 1)
        subsets = [
            (((self.data[:, 0] + (self.nexts[0] & mask)) >> current_index) & 3) == x
            for x in range(4)
        ]
        averages = np.array([np.average(self.traces[x, 0]) for x in subsets])
        difs = tuple(np.around(averages[1:] - averages[:-1]).astype(int))
        if difs not in hd:
            raise ValueError('{}'.format(current_index))
        patterns = np.array(hd[difs]).astype(self.sha2.dtype)
        self.prevs = np.array(
            [
                glue(prev, pattern, current_index)
                for prev in self.prevs for pattern in patterns
                if fit(prev, pattern, current_index)
            ]
        )
        if self.verbose:
            if len(self.prevs) > 1:
                print()
            for i, (a, e) in enumerate(self.prevs):
                print(
                    (
                        'Bit {:2d} option {:4d}: {}'
                        + ' ' * (self.sha2.nibble_count * 3 + 4)
                        + '{}'
                    ).format(
                        current_index,
                        i,
                        self.sha2.show(a, current_index + 1),
                        self.sha2.show(e, current_index + 1),
                    )
                )

    def find_bit_before_mismatch(self, bit_index):
        """Substage 1a (section 3.4.1) up to the least significant mismatching
        bit between DeltaA_0 and DeltaE_0 (case 1 in section 3.4.1)"""

        assert bit_index >= self.known_bits
        unknown_bits = bit_index + 1 - self.known_bits
        mask = (1 << (unknown_bits + 1)) - 1
        subsets = [
            (((self.data[:, 0] + self.nexts[0]) >> self.known_bits) & mask) == x
            for x in range(1 << (unknown_bits + 1))
        ]
        averages = np.array([np.average(self.traces[x, 0]) for x in subsets])
        rotated = [
            np.concatenate((averages[i:], averages[:i]))[: 1 << unknown_bits]
            for i in (1, 1 << unknown_bits, 1 + (1 << unknown_bits))
        ]
        leaps = np.around(
            averages[: 1 << unknown_bits] - rotated[0] - rotated[1] + rotated[2]
        ).astype(int)
        indices = np.array(np.nonzero(leaps)[0])

        # Subcase 1.1
        if len(indices) == 0:
            if self.verbose:
                print(
                    (
                        'Bit {:2d}, found up to {:2d}'
                        + ' ' * ((self.sha2.nibble_count + 1) * 8)
                        + '{} {}'
                    ).format(
                        bit_index,
                        self.known_bits - 1,
                        self.sha2.show(self.nexts[0], self.known_bits - 1),
                        self.sha2.show(self.nexts[1], self.known_bits - 1),
                    )
                )
            return

        # Subcase 1.2
        if len(indices) == 1:
            self.nexts += self.sha2.dtype(
                ((1 << unknown_bits) - 1 - indices[0]) << self.known_bits
            )
            self.known_bits = bit_index + 1
            if abs(leaps[indices[0]]) != 4:
                raise ValueError('{}'.format(bit_index))
            if self.verbose:
                print(
                    (
                        'Bit {:2d}, found up to {:2d}'
                        + ' ' * ((self.sha2.nibble_count + 1) * 8)
                        + '{} {}'
                    ).format(
                        bit_index,
                        self.known_bits - 1,
                        self.sha2.show(self.nexts[0], self.known_bits - 1),
                        self.sha2.show(self.nexts[1], self.known_bits - 1),
                    )
                )
            return

        # Subcase 1.3 - the first mismatch between DeltaA_0 and DeltaE0
        if len(indices) == 2:
            # From now on, call self.find_bit for every step
            self.find_bit = self.find_bit_after_mismatch
            self.nexts += (((1 << unknown_bits) - 1 - indices) << self.known_bits).astype(
                self.sha2.dtype
            )
            self.known_bits = bit_index + 1
            if any(abs(leaps[index]) != 2 for index in indices):
                raise ValueError('{}'.format(bit_index))
            if self.verbose:
                print(
                    (
                        'Bit {:2d}, found up to {:2d}'
                        + ' ' * ((self.sha2.nibble_count + 1) * 8)
                        + '{} {}'
                    ).format(
                        bit_index,
                        self.known_bits - 1,
                        self.sha2.show(self.nexts[0], self.known_bits - 1),
                        self.sha2.show(self.nexts[1], self.known_bits - 1),
                    )
                )
                print('\nStage 1b - finding A, E until the first mismatch')
            for current_index in range(bit_index):
                self.update_prevs(current_index, self.hd_eq)
            self.prevs[:, 1] ^= 1 << bit_index
            self.update_prevs(bit_index, self.hd_ne)
            if self.verbose:
                print('\nStage 1c - finding A, E, deltaA, deltaE after the first mismatch')
            self.prevs[:, 1] ^= 2 << bit_index
            return

        raise ValueError('{}'.format(bit_index))

    def find_bit_after_mismatch(self, bit_index):
        """Substages 1a (section 3.4.1) and 1b (section 3.4.2) simultaneously
        after the first mismatch between DeltaA_0 and DeltaE_0 (case 2 in
        section 3.4.1)"""

        assert bit_index == self.known_bits

        nexts = [self.nexts[i] for i in (0, 1)]
        subsets = [
            ((((self.data[:, 0] + nexts[0]) >> self.known_bits) & 3) == x)
            * ((((self.data[:, 0] + nexts[1]) >> self.known_bits) & 3) == y)
            for (x, y) in ((0, 0), (1, 0), (1, 1), (2, 1), (2, 2), (3, 2), (3, 3), (0, 3))
        ]
        averages = np.array([np.average(self.traces[x, 0]) for x in subsets])
        rotated = [np.concatenate((averages[i:], averages[:i]))[:4] for i in (1, 4, 5)]
        leaps = np.around(averages[:4] - rotated[0] - rotated[1] + rotated[2]).astype(int)
        indices = [i for i in range(leaps.shape[0]) if leaps[i] != 0]
        if len(indices) != 2:
            raise ValueError('{}'.format(bit_index))
        if any(abs(leaps[index]) != 2 for index in indices):
            raise ValueError('{}'.format(bit_index))
        if indices not in ([0, 1], [0, 3], [1, 2], [2, 3]):
            raise ValueError('{}'.format(bit_index))
        mask = self.sha2.dtype(1 << bit_index)
        big_mask = self.sha2.dtype(1 << (bit_index + 1))
        for i in (0, 1):
            if i in indices:
                self.nexts[i] ^= mask
                self.prevs[:, i] ^= mask
                if leaps[i] > 0:
                    self.prevs[:, i] ^= big_mask
            elif leaps[i + 2] > 0:
                self.prevs[:, i] ^= big_mask
        if self.nexts[1] > self.nexts[0]:
            self.nexts = self.nexts[::-1]
            self.prevs = self.prevs[:, ::-1]
        self.known_bits += 1

        if self.verbose:
            if len(self.prevs) > 1:
                print()
            for i, (a, e) in enumerate(self.prevs):
                print(
                    (
                        'Bit {:2d} option {:4d}: {}'
                        + ' ' * (self.sha2.nibble_count * 3 + 4)
                        + '{}'
                        + ' ' * (self.sha2.nibble_count * 3 + 6)
                        + '{} {}'
                    ).format(
                        bit_index,
                        i,
                        self.sha2.show(a, bit_index + 1),
                        self.sha2.show(e, bit_index + 1),
                        self.sha2.show(self.nexts[0], bit_index),
                        self.sha2.show(self.nexts[1], bit_index),
                    )
                )

    def finalize(self):
        """Convert self.prevs and self.nexts into a list of hypotheses for
        stage 2 (section 3.4.3)"""
        return [
            Stage1hypo(
                nextA=self.nexts[i] ^ a,
                prevA=self.prevs[m][i] ^ a,
                nextE=self.nexts[j] ^ b,
                prevE=self.prevs[m][j] ^ b,
            )
            for (i, j) in ((1, 0), (0, 1))
            for m in range(self.prevs.shape[0])
            for a in (self.sha2.dtype(0), self.sha2.dtype((1 << self.sha2.bit_count - 1)))
            for b in (self.sha2.dtype(0), self.sha2.dtype((1 << self.sha2.bit_count - 1)))
        ]


class Stage2state:
    def __init__(self, sha2, ae_hypo, data, traces, verbose):
        self.sha2 = sha2
        self.a = [sha2.dtype(0)] * 3 + [sha2.dtype(ae_hypo.prevA), ae_hypo.nextA + data[:, 0]]
        self.e = [sha2.dtype(0)] * 3 + [sha2.dtype(ae_hypo.prevE), ae_hypo.nextE + data[:, 0]]
        self.data = data
        self.traces = traces
        self.sigma1 = sha2.s1(self.e[4])
        self.sigma0 = sha2.s0(self.a[4])
        self.nextA = sha2.dtype(ae_hypo.nextA)
        self.nextE = sha2.dtype(ae_hypo.nextE)
        self.verbose = verbose

    def find_bit(self, bit_index):
        mask = self.sha2.dtype((1 << bit_index) - 1)
        point_mask = self.sha2.dtype(1 << bit_index)
        sum_en = self.sigma1 + self.data[:, 1] + self.sha2.round_const[1]
        sum_e = self.e[4] ^ (
            sum_en + (self.sha2.ch(self.e[4], self.e[3], self.e[2]) & mask) + (self.a[1] & mask)
        )
        subsets_e = [
            [
                (((sum_e >> bit_index) & 1) == i) * (((self.e[4] >> bit_index) & 1) == j)
                for j in (0, 1)
            ]
            for i in (0, 1)
        ]
        averages_e = [
            [np.average(self.traces[subsets_e[i][j], 1]) for j in (0, 1)] for i in (0, 1)
        ]
        diff_cg = np.around(averages_e[1][1] - averages_e[0][1]).astype(int)
        if abs(diff_cg) != 1:
            raise ValueError('CG error')
        self.a[1] ^= (self.sha2.dtype(diff_cg == -1) << self.sha2.dtype(bit_index)) ^ (
            self.e[3] & point_mask
        )
        diff_f = np.around(averages_e[1][0] - averages_e[0][0]).astype(int)
        if abs(diff_f) != 1:
            raise ValueError('F error')
        self.e[2] ^= (
            self.sha2.dtype((diff_f == -1) ^ (diff_cg == -1)) << self.sha2.dtype(bit_index)
        ) ^ (self.e[3] & point_mask)

        big_mask = (1 << (bit_index + 1)) - 1
        sum_an = sum_en + self.sigma0 + (self.sha2.maj(self.a[4], self.a[3], self.a[2]) & mask)
        sum_an2 = (
            sum_an
            + (self.e[1] & mask)
            + (self.sha2.ch(self.e[4], self.e[3], self.e[2]) & big_mask)
        )
        sum_a = self.a[4] ^ sum_an2
        subsets_a = [
            [
                (((sum_a >> bit_index) & 1) == i)
                * ((((self.a[4] ^ self.a[3]) >> bit_index) & 1) == j)
                for j in (0, 1)
            ]
            for i in (0, 1)
        ]
        averages_a = [
            [np.average(self.traces[subsets_a[i][j], 1]) for j in (0, 1)] for i in (0, 1)
        ]
        diff_g = np.around(averages_a[1][0] - averages_a[0][0]).astype(int)
        if abs(diff_g) != 1:
            raise ValueError('G error')
        self.e[1] ^= (self.sha2.dtype(diff_g == -1) << self.sha2.dtype(bit_index)) ^ (
            self.a[3] & point_mask
        )
        diff_b = np.around(averages_a[1][1] - averages_a[0][1]).astype(int)
        if abs(diff_b) != 1:
            raise ValueError('B error')
        self.a[2] ^= (self.sha2.dtype(diff_b == -1) << self.sha2.dtype(bit_index)) ^ (
            self.e[1] & point_mask
        )

        if self.verbose:
            print(
                (
                    'Bit {:2d}'
                    + ' ' * 14
                    + self.sha2.formatter
                    + '{} {}'
                    + ' ' * (self.sha2.nibble_count + 2)
                    + self.sha2.formatter
                    + '{} {}'
                ).format(
                    bit_index,
                    self.a[3],
                    self.sha2.show(self.a[2], bit_index),
                    self.sha2.show(self.a[1], bit_index),
                    self.e[3],
                    self.sha2.show(self.e[2], bit_index),
                    self.sha2.show(self.e[1], bit_index),
                )
            )

    def finalize(self):
        """Find the rest of the initial stage (Section 3.5.1)"""

        self.a[1] -= self.e[1]
        self.e[0] = (
            self.nextA
            - self.sha2.s0(self.a[3])
            - self.sha2.maj(self.a[3], self.a[2], self.a[1])
            - self.sha2.s1(self.e[3])
            - self.sha2.ch(self.e[3], self.e[2], self.e[1])
            - self.sha2.round_const[0]
        )
        self.a[0] = (
            self.nextE
            - self.sha2.s1(self.e[3])
            - self.sha2.ch(self.e[3], self.e[2], self.e[1])
            - self.e[0]
            - self.sha2.round_const[0]
        )

        if self.verbose:
            print(
                ('\nCandidate state:    ' + self.sha2.formatter * 8 + '\n').format(
                    self.a[3],
                    self.a[2],
                    self.a[1],
                    self.a[0],
                    self.e[3],
                    self.e[2],
                    self.e[1],
                    self.e[0],
                )
            )

        return self.a[:-1][::-1] + self.e[:-1][::-1]


def stage1(sha2, data, traces, verbose):
    """Stage 1 (section 3.4)"""

    state = Stage1state(sha2, data, traces, verbose)
    if verbose:
        print('\nStage 1a - finding deltaA, deltaE until the first mismatch\n')
    for bit_index in range(sha2.bit_count - 1):
        state.find_bit(bit_index)

    return state.finalize()


def stage2(sha2, data, traces, stage1_hypos, verbose):
    """Stage 2 (section 3.5)"""

    results = []
    if verbose:
        print('\nStage 2 - finding B,C,F,G\n')
    for stage1_hypo in stage1_hypos:
        stage2state = Stage2state(sha2, stage1_hypo, data, traces, verbose)
        if verbose:
            print(
                (
                    'Stage 1 hypothesis: '
                    + sha2.formatter
                    + ' ' * (sha2.nibble_count * 3 + 3)
                    + sha2.formatter
                    + '\n'
                ).format(
                    stage1_hypo.prevA,
                    stage1_hypo.prevE,
                    stage1_hypo.nextA,
                    stage1_hypo.nextE,
                )
            )
        try:
            for bit_index in range(sha2.bit_count):
                stage2state.find_bit(bit_index)
            results.append(stage2state.finalize())
        except ValueError:
            if verbose:
                print('The hypothesis is rejected\n')

    return results


def sha2_attack(sha2, data, traces, second_stage_count, filter_hypo=None, verbose=False):
    """Full attack on SHA256.

    Returns:
    1) a list of candidates for the secret initial state;
    2) the number of hypotheses found at stage 1.
    """
    stage1_hypos = stage1(sha2, data, traces, verbose)
    if filter_hypo:
        stage1_hypos = filter_hypo(stage1_hypos)
    results = stage2(
        sha2, data[:second_stage_count], traces[:second_stage_count], stage1_hypos, verbose
    )
    if len(results) == 0:
        raise ValueError('{}'.format(sha2.bit_count))

    return results, len(stage1_hypos)
