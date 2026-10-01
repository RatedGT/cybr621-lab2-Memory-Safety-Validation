# CYBR 621 Lab 2 – AI Code Review, Static Analysis & Memory Safety

**Name:** Gregory Theriault

**Course:** CYBR 621 – Secure System Programming, Metropolitan State University

**Environment:** GitHub Codespaces (Linux), GCC, ASan/UBSan, Semgrep, CodeQL (`gh codeql`)

## Overview
Two AI assistants generated C programs that append a username and message to `userlog.txt`.
- `assistant1.c`: basic prompt (ChatGPT - 5.6-Luna - free version)
- `assistant2.c`: "secure" prompt (input validation, safe file handling) (Claude - Opus 5.5 Medium - pro plan)

Both programs were built, tested, scanned, remediated, and revalidated. All evidence was saved
before and after remediation so results can be compared and reproduced.

## Repository Contents
| Path | Description |
|---|---|
| `assistant1.c` | Assistant 1 source **after** remediation (Fix A applied) |
| `assistant2.c` | Assistant 2 source (unchanged; already used `open()` 0600 and `gmtime_r()`) |
| `semgrep.yml` | Custom Semgrep rules (localtime, unsafe string functions) |
| `evidence/before/` | Original AI source and all outputs before remediation |
| `evidence/after/` | Remediated source and all outputs after remediation |

### Evidence file naming
Files are prefixed with the handout step number:
- `05/06-compile-*`: GCC `-Wall -Wextra -Wpedantic` output (empty = zero warnings)
- `07/08-run-*`: normal runs
- `09/10-noargs-*`: missing-argument tests
- `11-longuser-a1.txt`: oversized username test
- `12-inject-*`, `12-userlog.txt`: CR/LF log-injection tests and resulting log
- `14-san-long-*`: 5,000-character input under ASan/UBSan
- `16/17-semgrep-*`, `semgrep-results.json`: Semgrep registry and custom-rule scans
- `codeql-results.sarif`, `21-codeql-count.txt`, `22-codeql-findings.txt`: CodeQL security-and-quality results
- `23-umask.txt`: umask and `stat` of `userlog.txt`
- `after/23b-acl-test.txt`: `touch` permission test, mount info, umask, and `getfacl` output

## Remediation
**Fix A (assistant1.c only):** replaced `fopen("userlog.txt", "a")` (requests mode 0666) with
`open(..., O_WRONLY | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR)` + `fdopen()`. Added `close(fd)`
if `fdopen()` fails so the descriptor is not leaked.

**Fix B (localtime → localtime_r) was not applied.** Neither generated program called `localtime()`:
Assistant 1 used `ctime_r()` and Assistant 2 used `gmtime_r()`.

## Key Results
| Check | Before | After |
|---|---|---|
| CodeQL findings | 2 | 1 |
| `cpp/world-writable-file-creation` (assistant1.c:16) | Present | **Resolved** |
| `cpp/constant-comparison` (assistant2.c:310) | Present | Remains (redundant `fd >= 0` check; low severity) |
| `userlog.txt` permissions | `-rw-rw-rw- 666` | `-rw------- 600` |
| Assistant 1 log injection (`FAKE_ADMIN` line) | Succeeds | Still succeeds (no input validation; not detected by any scanner) |
| Assistant 2 log injection | Rejected | Rejected |

## Notable Finding: Default ACLs Override umask
The handout expects umask `0022` to reduce a 0666 request to 0644. In this Codespace the log file
was created **666 (world-writable)** despite umask `0022`. `getfacl` showed default ACLs on the
repository directory (`default:user::rwx`, `default:group::rwx`, `default:other::rwx`). When a
directory has default ACLs, Linux ignores the umask for new files. A controlled `touch` test
confirmed it: 666 in the workspace and 646 in `/tmp`, which matches `/tmp`'s default ACL. The CodeQL
world-writable finding was therefore a **true positive** in this environment. Explicit 0600 mode
bits in the code fixed it regardless of environment.

## Reproducing
```bash
gcc -Wall -Wextra -Wpedantic -o assistant1 assistant1.c
gcc -Wall -Wextra -Wpedantic -o assistant2 assistant2.c
semgrep scan --config semgrep.yml assistant1.c assistant2.c
gh codeql database create ./codeql-db --language=cpp \
  --command='gcc -Wall -Wextra -Wpedantic -c assistant1.c assistant2.c' --overwrite
gh codeql database analyze ./codeql-db \
  'codeql/cpp-queries:codeql-suites/cpp-security-and-quality.qls' \
  --format=sarif-latest --output=codeql-results.sarif --download
```
`codeql-db/`, compiled binaries, and `userlog.txt` are excluded via `.gitignore`.
