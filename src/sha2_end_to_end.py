import random
from sha2_attack import sha2_attack, Stage1hypo
from sha2_trace_generation import generate_traces


def end_to_end_attack(sha2, trace_count, second_stage_count, noise, experiment_count,
             seed=None, filter_hypo=True, verbose=False):
    def filter_hypotheses(stage1_hypos):
        hypo = Stage1hypo(iv[8], iv[0], iv[9], iv[4])
        if hypo in stage1_hypos:
            return [hypo]
        raise ValueError('{}'.format(sha2.bit_count))

    result_success_count, lsb_success_count = 0, 0
    if seed is None:
        seed = random.getrandbits(32)
    for i in range(experiment_count):
        # Generate the traces
        data, traces, iv = generate_traces(sha2, trace_count, seed + i, noise)
        if verbose:
            print('\n' + ' ' * 20 + (' ' * sha2.nibble_count).join(('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'))
                  + ' ' * (sha2.nibble_count + 2) + 'DeltaA   DeltaE')
            print(('The initial state:  ' + sha2.formatter * 8 + '  ' + sha2.formatter * 2).format(*iv))
        try:
            # Perform the attack
            if not verbose and not filter_hypo:
                print('{:8d}'.format(seed + i), end=' ')
            results, count = sha2_attack(sha2, data, traces, second_stage_count,
                                         filter_hypotheses if filter_hypo else None, verbose)
            # Errors in stage 2 are exceptionally rare. If one happens, we count only one correct word
            # although in fact it may be more
            lsb_success_count += 2 * sha2.bit_count if iv[:8] in results else sha2.bit_count
            result_success_count += 1
            # Print the results
            if verbose:
                print('The remaining candidates:')
            elif not filter_hypo:
                print('Success {:5d} {:3d}'.format(count, len(results)))
            for result in results:
                if verbose:
                    print((' ' * 20 + sha2.formatter * 8 + '  {}')
                          .format(*result, 'correct' if result == iv[:8] else 'wrong'))
        except ValueError as error_index:
            lsb_success_count += int('{}'.format(error_index))
            if verbose or not filter_hypo:
                print('Failure: bit {}'.format(error_index))
    return result_success_count / experiment_count * 100, \
        lsb_success_count / experiment_count / (2 * sha2.bit_count) * 100
