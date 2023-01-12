#  Copyright © 2022-2023 [unidentified]
#
#  All Rights Reserved.

import warnings
import argparse

from sha2 import Sha256, Sha512
from sha2_end_to_end import end_to_end_attack


def parse():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-b',
        '--bit-count',
        type=int,
        choices=[32, 64],
        default=32,
        help='Bit size of words - 32 for SHA256 or 64 for SHA512 (32 by default)',
    )
    parser.add_argument(
        '-t',
        '--trace-count',
        type=int,
        default=100000,
        help='Number of traces to acquire for the attack (100K by default)',
    )
    parser.add_argument(
        '-s',
        '--second-stage-count',
        type=int,
        default=20000,
        help='Number of traces to use for the second stage (20K by default)',
    )
    parser.add_argument(
        '-n',
        '--noise',
        type=float,
        default=None,
        help='Standard deviation of the normally distributed noise '
        'added to the trace (0 by default)',
    )
    parser.add_argument(
        '-e',
        '--experiment-count',
        type=int,
        default=1,
        help='Number of experiments to perform (1 by default)',
    )
    parser.add_argument(
        '-r',
        '--random-seed',
        type=int,
        default=None,
        help='Random seed for the secret generation (None by default)',
    )
    parser.add_argument(
        '-f',
        '--filter-hypo',
        action='store_true',
        help='Perform the second stage only on the correct hypothesis',
    )
    parser.add_argument(
        '-v',
        '--verbose',
        action='store_true',
        help='Provide detailed printout',
    )

    args = parser.parse_args()
    assert not args.verbose or args.experiment_count == 1, \
        '"-v" is permitted only if the experiment count is 1 ("-e 1" or default)'

    return (
        Sha256 if args.bit_count == 32 else Sha512,
        args.trace_count,
        min(args.trace_count, args.second_stage_count),
        args.noise,
        args.experiment_count,
        args.random_seed,
        args.filter_hypo,
        args.verbose,
    )


if __name__ == '__main__':
    # Parse the command line
    (
        sha2,
        trace_count,
        second_stage_count,
        noise,
        experiment_count,
        seed,
        filter_hypo,
        verbose,
    ) = parse()
    # Suppress expected overflows in addition and subtraction
    warnings.filterwarnings('ignore', category=RuntimeWarning)
    result_ratio, lsb_success_ratio = end_to_end_attack(
        sha2, trace_count, second_stage_count, noise, experiment_count, seed, filter_hypo, verbose
    )
    if not verbose:
        print('{:5.2f}% correct answers'.format(result_ratio))
        print('{:5.2f}% correct least significant bits'.format(lsb_success_ratio))
