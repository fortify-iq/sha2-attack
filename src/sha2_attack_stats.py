from datetime import datetime
import warnings
from sha2 import Sha256, Sha512
from sha2_end_to_end import end_to_end_attack

if __name__ == '__main__':
    # Suppress expected overflows in 32-bit addition and subtraction
    warnings.filterwarnings('ignore', category=RuntimeWarning)
    with open('res.csv', 'wt') as f_res, open('lsb.csv', 'wt') as f_lsb:
        prev_time = datetime.now()
        header = ',,' + ','.join(str(1 << i) for i in range(11, 21))
        f_res.write(header)
        f_lsb.write(header)
        for sha2 in (Sha256, Sha512):
            start = 11
            for noise in (0, 4, 8, 16, 32, 64, 128):
                line_header = '\n{},{:3d},'.format(sha2.bit_count, noise)
                f_res.write(line_header)
                f_lsb.write(line_header)
                for trace_count_exp in range(11, 21):
                    if trace_count_exp < start:
                        f_res.write(',')
                        f_lsb.write(',')
                        continue
                    experiment_count = 1 << (min((34 - trace_count_exp) >> 1, 10))
                    cur_time = datetime.now()
                    print(
                        '{}\n{} {:2d} {:4d} '.format(
                            cur_time - prev_time, line_header, trace_count_exp, experiment_count
                        ),
                        end=''
                    )
                    prev_time = cur_time
                    trace_count = 1 << trace_count_exp
                    result_success_ratio, lsb_success_ratio = end_to_end_attack(
                        sha2, trace_count, trace_count, noise, experiment_count)
                    if lsb_success_ratio < 2:
                        start += 1
                    f_res.write('{},'.format(result_success_ratio))
                    f_lsb.write('{},'.format(lsb_success_ratio))
                    f_res.flush()
                    f_lsb.flush()
                    if result_success_ratio > 99:
                        break
