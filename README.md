# Simulator of the CDPA Based Attack on SHA2

## Description

This repository implements the CDPA based attack on SHA2 as described in the paper [Carry-based Differential Power Analysis (CDPA) and its Application to Attacking HMAC-SHA-2](https://tches.iacr.org/index.php/TCHES/article/view/10955/10262). For the attack on HMAC SHA2 described in the same paper, see the repository [https://github.com/fortify-iq/hmac-attack](https://github.com/fortify-iq/hmac-attack) which is dependent on this repository.

The attack assumptions are as follows. A device calculates the SHA2 (either 32-bit SHA256 or 64-bit SHA512) compression function, starting from a secret internal state, one round per clock cycle. The attacker feeds the device randomly distributed known inputs, and observes the side channel leakage traces. This is exactly what happens in the second application of the compression function in both the inner and outer hashes of HMAC SHA2, so this attack can be used to discover both of these internal states (by attacking first the inner hash and then the outer hash). This enables the attacker to forge the HMAC SHA2 tag for arbitrary messages. The leakage model assumes that the Hamming distance between the consecutive internal states leaks. Optionally, a normally distributed random noise is added. The attack implemented here uses only the first two Hamming distances, and (when successful) produces a small set of candidates for the secret initial internal state. The correct candidate can be subsequently found by predicting the Hamming distances in the later rounds and comparing them to the actual traces.

The repository contains two folders:

* `src` - The Python code that implements the attack
* `docs` - Statistical data produced using this code

Folder `src` contains the following files:

* `sha2.py` - implements basic building blocks and parameters of SHA256 and SHA512. Used in both the trace generation and the attack.
* `sha2_trace_generation.py` - generates traces for the attack on SHA2.
* `sha2_attack.py` - mounts the attack on SHA2.
* `sha2_end_to_end.py` - calls the trace generation function from `sha2_trace_generation.py`, calls the attack function from `sha2_attack.py`, and evaluates the result.
* `test_sha2_attack.py` - a command line utility which performs the attack on SHA2 in a loop using `sha2_end_to_end.py` and collects statistics.

Folder `docs` contains the following files:

* `sha2_attack_stats.xlsx` - a Microsoft Excel file containing the metrics M<sub>1</sub>, M<sub>2</sub> described in Section 2.3.5 of the CDPA paper measured for different configurations, and the graph based on this data which is shown in Figure 11 of the CDPA paper
* `res(M1).csv, lsb(M2).csv` - the two sheets of `sha2_attack_stats.xlsx` exported to the `csv` text format

## Installation

The most common way to install Python packages is by using the [pip](https://pip.pypa.io/en/stable/) package manager.

To install this library run:

```bash
python -m pip install git+https://github.com/fortify-iq/sha2-attack
```

Usually, `pip` is automatically installed, but if your Python distro is missing `pip` refer to [this guide](https://pip.pypa.io/en/stable/installation/) to install it.

## Usage of command-line utility

A command-line wrapper for `test_sha2_attack.py` entry point is installed along with the library:

`sha2-attack [-h] [-b BIT_COUNT] [-t TRACE_COUNT] [-s SECOND_STAGE_COUNT] [-n NOISE] [-e EXPERIMENT_COUNT] [-r RANDOM_SEED] [-f] [-v]`

- `-h` - Help.
- `-b` - Bit size (32 for SHA256, 64 for SHA5120). Default value 32 (SHA256).
- `-t` - Number of traces in one experiment. Default value 100K.
- `-s` - Number of traces to be used for stage 2. By default, the same number as used for stage 1.
- `-n` - Amplitude of normally distributed noise added to the traces. Default value 0 (no noise).
- `-e` - Number of experiments. Default value 1.
- `-r` - Random seed. If no random seed is provided, the experiments are not reproducible, since each time different random values are used. If a random seed is provided, the experiments are reproducible, and the same command line always produces the same result.
- `-f` - Filter hypotheses. After a successful completion of stage 1, performs stage 2 with only the correct hypothesis. (In some cases, the first stage generates as many as 2,048 hypotheses.)
- `-v` - Verbose. Permissible only if the number of experiments is 1 (which is the default). Prints a detailed log of all the steps of the attack.

Unless option `-f` is used, for every experiment a line is printed out. It includes the RNG seed used to generate the traces and the noise, the result (Success/Failure), and some additional information. If the number of experiments is large, using option `-f` is recommended in order to save time and suppress this printout.

In any case, the two last lines of the printout of the utility are:

```text
xx.xx% correct answers
yy.yy% correct least significant bits
```

These two lines reflect the estimations of metrics M<sub>1</sub>, M<sub>2</sub> described in Section 2.3.5 of the CDPA paper, based on the performed set of experiments.

## Reproducing the Results from the CDPA Paper

Table 2 is based on the data in file `docs/sha2_attack_stats.xlsx`, sheet `res(M1)`. For example, the upper left entry (2<sup>16</sup> for SHA256, noise 0) reflects the fact that the first entry in row 3 of this sheet (SHA256, noise 0) which is greater that 50% is in cell G3, corresponding to 65,536=2<sup>16</sup> traces.

All the values in `docs/sha2_attack_stats.xlsx` can be reproduced using this utility. For example, in order to reproduce cell G3 in the two sheets of `docs/sha2_attack_stats.xlsx`, use, e.g., the following command line:

```bash
sha2-attack -b 32 -n 0 -t 65536 -e 100 -f
```

The number of experiments (parameter `-e`) can be chosen arbitrarily, taking into account that both the precision and the run time increase as the number of experiments increases. The docs may slightly deviate from the data in `docs/sha2_attack_stats.xlsx`, since the metrics are estimated on a randomly chosen finite set of experiments.
