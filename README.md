# Simulator of the CDPA Based Attack on SHA2

The attack assumptions are as follows. A device calculates SHA2 (either 32-bit SHA256 or 64-bit SHA512) compression function, starting from a secret internal state, one round per clock cycle. The attacker can feed randomly distributed known inputs, and observes the side channel leakage trace. This is exactly what happens in the second application of the compression function in both the inner and outer hashes of HMAC SHA2, so this attack can be used to find out both these internal states (by attacking first the inner hash and then the outer hash) which enables time to forge HMAC SHA2 of arbitrary messages. The leakage model assumes that the Hamming distance between the consecutive internal states leaks; optionally, a normally distributed random noise is added. The attack implemented here uses only two first Hamming distances, and (when successful) produces a small set of candidates for the secret initial internal state. The correct candidate can be subsequently found by predicting the Hamming distances in the later rounds and comparing them against the actual traces.

The repository contains two directories:
* `src` - Python code implementing the attack
* `docs` - Excel spreadsheets with statistical data produced by script `src/sha2_attack_stats.py`

Directory `src` contains the following files:
* `sha2.py` - implements basic building blocks and parameters of SHA256 and SHA512. Used in both the trace generation and the attack
* `sha2_trace_generation.py` - generates traces for the attack on SHA2
* `sha2_attack.py` - mounts the attacks on SHA2
* `sha2_end_to_end.py` - calls the traces generation function from `sha2_trace_generation.py`, calls the attack function from `sha2_attack.py`, and evaluates the result
* `test_sha2_attack.py` - command line utility which performs the attack on SHA2 in a loop using `end-to-end.py` and collects statistics
* `sha2_attack_stats` - command line utility which collects a comprehensive statistics using `sha2_end-to-end.py`

## Usage of `test_cdpa_attack.py`
`test_sha2_attack.py [-h] [-b BIT_COUNT ] [-s SHARE_COUNT] [-t TRACE_COUNT] [-n NOISE] [-e EXPERIMENT_COUNT] [-r RANDOM_SEED] [-v] [-l]`

- `-h` - Help.
- `-b` - Bit size of the secrets (1-64). Default value 32.
- `-t` - Number of traces in one experiment. Default value 100K.
- `-n` - Amplitude of normally distributed noise added to the traces. By default no noise (= amplitude 0).
- `-e` - Number of experiments. Default value 1.
- `-r` - Random seed (by default `None`). If no random seed is provided, the experiments are not reproducible, since each time different random values are used. If a random seed is provided, the experiments are reproducible, and the same command line always produces the same result.
- `-v` - Verbose. Permissible only if the number of experiments is 1 (which is the default). Outputs a summary of the rounds corresponding to bits 0-7 (or less if the bit size is less than 8).

## Dependencies installation

Implemented attack codebase has a few dependencies.

The simplest way to install them is to use [pip](https://pip.pypa.io/en/stable/) package manager.
List of dependencies is contained within `requirements.txt` file,
use command described [here](https://pip.pypa.io/en/stable/user_guide/#requirements-files) to install them.
