# Simulator of the CDPA Based Attack on SHA2

The attack assumptions are as follows. A device calculates the SHA2 (either 32-bit SHA256 or 64-bit SHA512) compression function, starting from a secret internal state, one round per clock cycle. The attacker feeds randomly distributed known inputs, and observes the side channel leakage traces. This is exactly what happens in the second application of the compression function in both the inner and outer hashes of HMAC SHA2, so this attack can be used to discover both of these internal states (by attacking first the inner hash and then the outer hash). This enables the attacker to forge the HMAC SHA2 tag for arbitrary messages. The leakage model assumes that the Hamming distance between the consecutive internal states leaks; optionally, a normally distributed random noise is added. The attack implemented here uses only the two first Hamming distances, and (when successful) produces a small set of candidates for the secret initial internal state. The correct candidate can be subsequently found by predicting the Hamming distances in the later rounds and comparing them to the actual traces.

The repository contains two directories:
* `src` - Python code implementing the attack
* `docs` - An Excel spreadsheet with statistical data`

Directory `src` contains the following files:
* `sha2.py` - implements basic building blocks and parameters of SHA256 and SHA512. Used in both the trace generation and the attack.
* `sha2_trace_generation.py` - generates traces for the attack on SHA2.
* `sha2_attack.py` - mounts the attack on SHA2.
* `sha2_end_to_end.py` - calls the trace generation function from `sha2_trace_generation.py`, calls the attack function from `sha2_attack.py`, and evaluates the result.
* `test_sha2_attack.py` - command line utility which performs the attack on SHA2 in a loop using `end-to-end.py` and collects statistics.

## Usage of `test_cdpa_attack.py`
`test_sha2_attack.py [-h] [-b BIT_COUNT ] [-t TRACE_COUNT] [-s SECOND_STAGE_COUNT] [-n NOISE] [-e EXPERIMENT_COUNT] [-r RANDOM_SEED] [-f] [-v]`

- `-h` - Help.
- `-b` - Bit size (32 for SHA256, 64 for SHA5120). Default value 32 (SHA256).
- `-t` - Number of traces in one experiment. Default value 100K.
- `-s` - Number of traces to be used for stage 2. Default value 20K.
- `-n` - Amplitude of normally distributed noise added to the traces. Default value 0 (no noise).
- `-e` - Number of experiments. Default value 1.
- `-r` - Random seed. If no random seed is provided, the experiments are not reproducible, since each time different random values are used. If a random seed is provided, the experiments are reproducible, and the same command line always produces the same result.
- `-f` - Filter hypotheses. After a successful completion of stage 1, perform stage 2 only with the correct hypothesis. (In some cases, the first stage generates as many as 2,048 hypotheses.)
- `-v` - Verbose. Permissible only if the number of experiments is 1 (which is the default). Outputs a summary of the rounds corresponding to bits 0-7 (or less if the bit size is less than 8).

## Installation of Dependencies

The codebase of the attack has a few dependencies.

The simplest way to install them is by using the [pip](https://pip.pypa.io/en/stable/) package manager.
The list of dependencies is contained within the `requirements.txt` file.
Use the commands described [here](https://pip.pypa.io/en/stable/user_guide/#requirements-files) to install the dependencies.
