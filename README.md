# Harpocrates

This repository contains a test pack and a test runner for screening x86-64 CPU cores for silicon defects that may lead to silent data corruption: cases where a core computes a wrong result without raising any error.

The pack contains 624 short instruction sequences generated with the Harpocrates methodology [1, 2]. The runner executes them back to back on each core, compares the results across cores, and reports any core whose results differ from the others. The tests have been run on various x86-64 CPUs.

**Disclaimer.** The sequences were optimized for detection on the micro-architectural configurations modelled in the papers (see below). On other micro-architectures their effectiveness is not guaranteed.

## Building

```bash
make
```

This needs gcc and binutils on Linux x86-64 and produces `./harprun`, a static binary with no other dependencies. The CPU must support SSE4.2. Each worker uses about 80 MB of memory, so on a machine with many cores and little memory you may want to give `--cpus` a subset of the CPUs.

## Running

The usual way to run the pack is to let all CPUs vote:

```bash
./harprun --pack packs/harpocrates-v1.hpk --cpus all --rounds 3 --json-file harprun.json
```

This starts one worker per CPU, runs every test three times on each of them, and compares the results. When it finishes, the runner prints a short summary (the outcome, how much work was completed, and any findings) and saves the full JSON report to `harprun.json`. A round over the whole pack takes about 20 seconds on a recent desktop.

If you leave out `--json-file`, the report is still saved, in the current directory, as `harprun-YYYYMMDD-HHMMSS-XXXXXX.json`; the timestamp and unique suffix keep the reports of earlier runs intact. With `--json-file -` the JSON is written to standard output and the summary to standard error, so it can be piped into other tools. With `--output text` the runner prints the detailed report as text, followed by the summary, and saves no JSON file.

### Options

| Option | Meaning |
|---|---|
| `--pack FILE` | The test pack to run (required). |
| `--cpus all` or `--cpus 0-7,16-23` | Voting mode: start one worker on each listed CPU. |
| `--rounds N` | Voting mode: how many times each CPU goes through the selected tests (default 1). |
| `--group-by auto` or `none` | Voting mode: compare cores within each core design (the default), or compare all listed CPUs with each other. |
| `--cpu N` | Single-core mode: run on CPU N. Without it, the run stays on the CPU it starts on. |
| `--dump ID` | Single-core mode: also print the registers captured from that test. |
| `--repeats R` | How many times each test is executed in a row (default 1). Completed executions are compared for stability; timeouts are reported separately. |
| `--only ID` | Run only this test. Can be given several times. |
| `--max-seconds S` | Stop test execution after S seconds and report what was completed. |
| `--tick-ms T` | Each execution gets `2 × T` milliseconds of CPU time (default 5000: a 10-second CPU allowance). Time waiting to be scheduled does not consume it. |
| `--worker-wait-seconds S` | Voting mode: maximum elapsed time waiting for a worker to start or make progress (default 60). Must exceed `2 × T / 1000` seconds. Expiry makes the run partial. |
| `--flags-mask HEX` | Which RFLAGS bits are part of the signature (default 0xcd5). |
| `--output json` or `text` | Format of the full report. JSON (the default) is saved to a file; `text` is printed. A short summary is printed in both cases. |
| `--json-file PATH` | Where to save the JSON report. `-` writes it to standard output instead. |
| `--brief` | List only the tests and cores that are not clean. |
| `--check` | Validate and load the pack without running anything. |
| `--version` | Print the runner version. |


### Exit codes

| Code | Meaning |
|---|---|
| 0 | The run completed without findings; in voting mode, the cores agreed on every test. |
| 1 | The command line was not understood. |
| 2 | The CPU is not supported, or the pack is damaged or incompatible. |
| 3 | There is a finding (see below). This takes precedence over code 5. |
| 4 | An internal error occurred, or the report could not be written. |
| 5 | There is no finding, but the run is incomplete. |

## Understanding the results

For every execution of a test, the runner computes a 64-bit signature of the state the test left behind: the registers, the flags, the vector state, the memory it wrote, the stack, and the fault if the test ended in one. Cores of the same design are expected to produce identical signatures, so the runner puts them in one group and lets each group vote on each test. Most CPUs form a single group; on a hybrid CPU the performance cores and the efficiency cores form separate groups. The report can contain the following:

- **Minority**: one core's signature differs from the one a strict majority of its group agrees on. This is the result that points to a specific core, and the report lists which parts of the state differed.
- **Unstable**: a core produced different completed-result signatures for the same test across `--repeats`.
- **Tie**: the cores of a group disagree, but no signature has a strict majority (for example, two cores that differ), so the runner cannot tell which one is wrong.
- **Timeouts**: an execution exhausted its CPU allowance. These make the run partial and are excluded from signature voting; the report records the affected CPU and test, number of timed-out executions, and the first timeout's zero-based repeat index, CPU time and elapsed time. Missing results do not reduce the voting quorum. If only one core times out, re-run that test.
- **Abnormal majority**: a strict majority produced the same unexpected signal outcome, or every voter timed out without a completed result. These leave the run partial; any disagreement among completed results is also reported.
- **Cross-group tests**: two groups each agree internally but differ from each other. This is expected when a test depends on flag bits that the architecture leaves undefined, and it is reported for information only.

A run is reported as partial (exit code 5) when it has no findings but the evidence is incomplete: for example, the time budget ran out, a test faulted or timed out, a group had only one core and so nothing to compare with, or a worker failed.

Please keep in mind that the pack does not ship reference signatures, so results are judged by agreement between the cores being tested. A defect that affects every core of a group in exactly the same way would go unnoticed, and a run on a single CPU can record signatures but has nothing to compare them with.

## The pack

`packs/harpocrates-v1.hpk` contains the 624 tests, named `t001` to `t624` (SHA-256 `48afe12f1c586c28a719c980fb2329190f34f70c71ecb732fe0091e0ce4011d9`).

A pack contains machine code that the runner executes directly on your machine, so please run only packs from a source you trust, and verify the checksum before use.

## In case of detections; contact us! 

You can open an issue in the repo with details of any abnormal event you notice!

## Citing

If you use the tests or the runner in your work, please cite [1], and [2] and [3] where relevant.

1. N. Karystinos, O. Chatzopoulos, G.-M. Fragkoulis, G. Papadimitriou, D. Gizopoulos and S. Gurumurthi, "Harpocrates: Breaking the Silence of CPU Faults through Hardware-in-the-Loop Program Generation," ACM/IEEE 51st Annual International Symposium on Computer Architecture (ISCA), 2024, pp. 516-531. [doi:10.1109/ISCA59077.2024.00045](https://doi.org/10.1109/ISCA59077.2024.00045)
2. N. Karystinos, G.-M. Fragkoulis, O. Chatzopoulos, D. Gizopoulos and S. Gurumurthi, "Harpocrates++: Automated Functional Program Generation Against CPU Faults and Silent Data Corruptions," IEEE Micro, vol. 46, no. 1, pp. 19-28, Jan./Feb. 2026. [doi:10.1109/MM.2025.3640385](https://doi.org/10.1109/MM.2025.3640385)
3. N. Karystinos, O. Chatzopoulos, D. Gizopoulos, A. Kumar, S. Gurumurthy, S. Gurumurthi and V. Sridharan, "Harpocrates-in-action: Using Simulation-based Functional Test Programs to Catch Marginal Defects in CPUs," 56th Annual IEEE/IFIP International Conference on Dependable Systems and Networks - Supplemental Volume (DSN-S), 2026, pp. 57-63. [doi:10.1109/DSN-S70715.2026.00024](https://doi.org/10.1109/DSN-S70715.2026.00024)

## Acknowledgements

This work was supported by AMD, Meta and the [Open Compute Project](https://www.opencompute.org/) (OCP).

## Licence

This repository is released under the Apache License, Version 2.0. The full text is in [LICENSE](LICENSE).
