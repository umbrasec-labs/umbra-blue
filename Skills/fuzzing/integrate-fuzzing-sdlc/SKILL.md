---
name: integrate-fuzzing-sdlc
description: "Defensive methodology for building fuzzing into your SDLC and CI so you find exploitable memory-safety and parsing bugs in your own code before an adversary fuzzes your released binaries to develop exploits (MITRE ATT&CK T1587.004, which names fuzzing, feeding T1190, T1203, and T1068). The log source is your build pipeline, not a SIEM: sanitizer reports (ASan, UBSan, MSan, TSan), libFuzzer and AFL++ crash output, OSS-Fuzz / ClusterFuzz / CIFuzz dashboards, coverage deltas, and crash stack-hash dedup in GitHub Actions or GitLab CI. Gives the signals, a CI gating approach, a corpus-triage hunt, and SDLC hardening mapped to ISO and NIST. Use when you want to add fuzzing to CI, triage a fuzzer crash, dedup and bug-bucket findings, decide whether a sanitizer report is exploitable and release-blocking, set up OSS-Fuzz or CIFuzz, or harden a library release process against bug-hunting attackers."
---

# Fuzzing in the SDLC - Defensive Methodology

> **Tier 2 - methodology skill.** No bespoke UMBRASEC detection rule ships with this skill yet. It gives the defender's method, the pipeline signals, the triage hunt, and the hardening, and it points to public, maintained sources by URL. Promotion to Tier 1 (a sourced, tuned UMBRASEC artifact) is tracked in [COVERAGE.md](https://github.com/umbrasec-labs/umbra-blue/blob/main/COVERAGE.md). Do not treat the content below as citing a UMBRASEC rule; there is none for this threat yet.

## TL;DR

Adversaries fuzz your shipped software to find the memory-corruption and parsing bugs they turn into exploits. You win by fuzzing the same code first, continuously, with sanitizers on, so the crash lands in your CI run instead of in a 0-day. Build short-running fuzz targets that run on every pull request (regression mode over the committed corpus) and long-running jobs out of band (OSS-Fuzz or a self-hosted ClusterFuzz). Treat an ASan or UBSan abort in a fuzz job exactly like a failed test: it blocks the merge. The hard part is not finding crashes, it is triaging them: dedup by sanitizer stack hash, bucket by root cause, decide exploitability, and map each live bug back to the released versions that carry it.

## What it looks like, defender view

This threat does not show up as an alert in your SOC. It shows up, if you are doing this right, as a reproducible crash inside your own build pipeline before release. The defender-side signal is a fuzz target exiting non-zero under a sanitizer, with a saved crashing input and a symbolized stack trace. The attacker-side activity it preempts (someone fuzzing your public binaries to build a capability) happens outside your telemetry entirely, which is exactly why MITRE notes T1587.004 cannot be mitigated with preventive controls in your environment. The leverage you do have is shifting the discovery left: the same `heap-buffer-overflow` ASan report, found by you at commit time, is a blocked merge; found by an adversary against a release, it is T1190 or T1203.

## Log sources and signals

The pipeline, not a SIEM, carries every signal here.

- **Sanitizer reports.** AddressSanitizer (`AddressSanitizer: heap-buffer-overflow`, `heap-use-after-free`, `stack-buffer-overflow`, `global-buffer-overflow`), UndefinedBehaviorSanitizer (`runtime error: signed integer overflow`, `index N out of bounds`, misaligned or null pointer use), MemorySanitizer (`use-of-uninitialized-value`), and ThreadSanitizer (`data race`). The report's first frame plus the error class is the bug's fingerprint. ASan exits with the process abort and writes the trace to stderr; capture stderr in the job log.
- **Fuzzer engine output.** libFuzzer prints `==ERROR` and writes the reproducer to `crash-<sha1>`; AFL++ writes to `out/default/crashes/` and tracks `saved_crashes`, `saved_hangs`, and `stability` in `fuzzer_stats`. A rising `saved_crashes` count or a non-empty crashes directory is the signal a CI step should fail on.
- **Coverage and corpus.** libFuzzer's `cov:` / `ft:` counters and an LCOV or `llvm-cov` report tell you whether the target is actually reaching new code or stalling. A fuzz target whose coverage has been flat for weeks is a blind spot, not a clean bill of health.
- **OSS-Fuzz / ClusterFuzz / CIFuzz.** For in-scope open-source projects, the ClusterFuzz dashboard and the issue tracker carry each bug's crash state, regression range (the commit that introduced it), minimized testcase, and silent-fix deadline. CIFuzz (the OSS-Fuzz GitHub Action) surfaces the same as a failed check on the pull request.
- **CI job metadata.** GitHub Actions or GitLab CI job logs and artifacts hold the crash corpus, the sanitizer trace, and the commit SHA under test. Retain crashing inputs as build artifacts so a finding is reproducible after the runner is gone, and scrub them for secrets, since fuzzers happily memorize any key that leaked into a seed.

What normal looks like: fuzz jobs pass, the corpus grows slowly, coverage climbs then plateaus per target, and `saved_crashes` stays at zero. The anomaly is any new crash bucket, a coverage cliff after a refactor, or a regression range that points at a recent commit.

## Detection approach

"Detection" here means a build gate, not a SIEM rule, so **no tuned UMBRASEC rule ships for this threat**; use the public, maintained frameworks below rather than a hand-rolled one.

Wrap the untrusted-input entry points (parsers, decoders, deserializers, protocol handlers, anything that touches attacker-controlled bytes) in fuzz targets built with libFuzzer or AFL++ and compiled with `-fsanitize=address,undefined` (add `fuzzer` and, for C/C++ reads of uninitialized memory, a separate MemorySanitizer build). Run two tiers:

- **Per-pull-request, fast:** run each target in regression mode over the committed seed corpus and the known crash reproducers for a bounded time (`-runs=` or a few seconds each). This is deterministic and gates the merge. Google's CIFuzz Action is the reference implementation of PR-time fuzzing, though it runs time-boxed fuzzing (the `fuzz-seconds` input, default 600) seeded from the OSS-Fuzz corpus rather than a pure deterministic replay.
- **Continuous, long-running:** run full fuzzing out of band on OSS-Fuzz (for eligible open-source projects) or a self-hosted ClusterFuzz, which handle scheduling, corpus management, crash dedup, minimization, and regression-range bisection for you.

Gate on the sanitizer exit, not on a pattern you grep for: if any target aborts under ASan/UBSan/MSan or a fuzzer writes a new crash file, the job fails and the merge is blocked. Dedup incoming crashes by the sanitizer's crash-state stack hash so one root cause does not open twenty tickets. For the language-specific engines, use the first-party tooling: Go's native `go test -fuzz`, Rust's `cargo fuzz` (libFuzzer) or `cargo afl`, Python's Atheris, and Jazzer for the JVM.

Public sources to anchor on, by URL: Google OSS-Fuzz and its ClusterFuzz and CIFuzz docs (`https://google.github.io/oss-fuzz/`), the LLVM libFuzzer reference (`https://llvm.org/docs/LibFuzzer.html`) and sanitizer docs (`https://clang.llvm.org/docs/AddressSanitizer.html`), AFL++ (`https://github.com/AFLplusplus/AFLplusplus`), OWASP SAMM's Security Testing practice (`https://owaspsamm.org/`), and MITRE D3FEND (`https://d3fend.mitre.org/`). ATT&CK itself lists the countering activity under T1587.004, not a detection analytic, because the fuzzing an adversary does happens off your network.

## Threat hunt

Hypothesis: a bug class an attacker would fuzz for already exists in a shipped version, and your current CI simply never exercised that path. Hunt it rather than waiting for a crash to appear.

1. **Inventory the attack surface.** List every function that parses attacker-reachable input and check it against your set of fuzz targets. Each unfuzzed parser is the hunt's priority queue; coverage reports confirm whether an existing target actually reaches it.
2. **Replay the full corpus against HEAD.** Run every saved reproducer and the whole seed corpus against the current build under all sanitizers. A crash here is a regression; a clean run tells you which historical bugs are closed.
3. **Bisect to a regression range.** For any live crash, use ClusterFuzz's regression range or `git bisect` with the reproducer as the test to find the introducing commit, then map that commit to the release tags that contain it. That set is the list of shipped versions carrying the bug and the input to your advisory and patch decision.
4. **Mine the corpus for secrets.** Grep saved inputs and seeds for tokens, keys, and internal hostnames a fuzzer may have retained. Scrub and rotate before the corpus is published or attached to a public issue.
5. **Watch for coverage cliffs.** Diff coverage per target across recent commits; a sudden drop means a refactor stopped exercising a path that used to be fuzzed, which is a silent blind spot an attacker's fuzzer would not share.

## Hardening

Shrink the window in which an adversary's fuzzer finds a bug before yours does, and reduce the exploitability of any bug that still ships. The controls below ground cleanly in the vulnerability-management row of the UMBRASEC [foundation guide](https://umbrasec.dev/guide/foundation.html) (Essential Eight *Patch applications*, ISO 27001:2022 **A.8.8**, NIST CSF 2.0 **ID.RA** and **PR.PS**); a cell is left blank where no single control maps.

| Control | What it does | Essential Eight | ISO 27001:2022 | NIST CSF 2.0 |
|---|---|---|---|---|
| Continuous fuzzing of input parsers in CI | Finds the memory-safety and parsing bugs an attacker would fuzz for, before release | - | A.8.8 Technical vulnerabilities | ID.RA |
| Ship fixes fast with a regression range | Bisect to the introducing commit, patch, and release so the bug's live-version window closes | Patch applications | A.8.8 Technical vulnerabilities | PR.PS Platform Security |
| Compile releases with runtime mitigations | Stack canaries, ASLR, DEP/NX, CFI, and fortified source raise exploitation cost on any bug that slips through | - | A.8.8 Technical vulnerabilities | PR.PS Platform Security |

Beyond the grounded table: adopt a memory-safe language or safe wrappers for new parsers where feasible, keep the corpus and crash reproducers under access control, and treat a sanitizer abort in CI as release-blocking by policy, not by reviewer discretion. OWASP SAMM's Security Testing practice is the maturity reference for institutionalizing this; D3FEND's platform-hardening countermeasures, for example Stack Frame Canary Validation (D3-SFCV), are the runtime complement that limits blast radius when a fuzzable bug does reach production.

## Honest limitations

Fuzzing finds crashes, not all vulnerabilities: logic flaws, authorization bugs, and most injection classes do not manifest as a sanitizer abort and will not surface here. Coverage-guided fuzzing can plateau at a hard checksum, length field, or state machine and never reach the vulnerable code behind it, so flat coverage is not safety. Not every crash is exploitable, and not every exploitable bug crashes, so triage still needs human judgement on reachability and impact; resist auto-filing every bucket as critical. A determined adversary with more compute, better seeds, or a custom harness can still out-fuzz you on a path you never targeted. And this is a pre-release control: it does nothing for a bug already live in a version you can no longer patch, which is why it pairs with runtime mitigations and a fast patch-and-advisory process rather than replacing them.

## ATT&CK and D3FEND

- MITRE ATT&CK: [T1587.004 Develop Capabilities: Exploits](https://attack.mitre.org/techniques/T1587/004/) (the page explicitly names fuzzing and patch analysis as the exploit-discovery methods). Bugs found this way are used via [T1190 Exploit Public-Facing Application](https://attack.mitre.org/techniques/T1190/), [T1203 Exploitation for Client Execution](https://attack.mitre.org/techniques/T1203/), and [T1068 Exploitation for Privilege Escalation](https://attack.mitre.org/techniques/T1068/).
- MITRE D3FEND: [Stack Frame Canary Validation (D3-SFCV)](https://d3fend.mitre.org/technique/d3f:StackFrameCanaryValidation) and the related platform-hardening countermeasures are the runtime mitigations that reduce the exploitability of the memory-corruption bug classes fuzzing surfaces. D3FEND models operational defenses, so it has no node for the development-time act of fuzzing your own code; the mapping above is the complementary runtime control, not a claim that D3FEND covers SDLC fuzzing.
- Public sources: [Google OSS-Fuzz / ClusterFuzz / CIFuzz](https://google.github.io/oss-fuzz/), [LLVM libFuzzer](https://llvm.org/docs/LibFuzzer.html), [Clang AddressSanitizer](https://clang.llvm.org/docs/AddressSanitizer.html), [AFL++](https://github.com/AFLplusplus/AFLplusplus), [OWASP SAMM Security Testing](https://owaspsamm.org/).

**Scope note.** This is a defensive skill. It explains the adversary's use of fuzzing only as far as needed to justify fuzzing your own code first and triaging the results, and it ships no fuzzing harnesses, exploit code, or offensive tooling.
