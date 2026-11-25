
# Forensics Integration 

### Overview
We added forensics logging to 10 python methods in KubeSec.
These are all the same 10 methods that fuzz.py targets, so every 
fuzzing rub also test the logging. The goal is that after a run, we
can rebuild waht each method was called with, it's decision, and 
where and why it failed. 

### Integration
We added in a new file called forensics_logger.py. 
This file contains a logger that is used in the 10 methods we modified. 
The logger writes to a file called forensics.log. 

parser.py, graphtaint.py, and scanner.py all import the logger and use it in the 10 methods 
we modified.

### Table of Modified Methods
| # | Method | File | What is logged |
|---|---|---|---|
| 1 | `checkIfWeirdYAML` | parser.py | Input type, warning on non-string input, result, traceback on failure |
| 2 | `keyMiner` | parser.py | Input type, whether a key path was found and its depth (not the path itself, since it ends in the matched value) |
| 3 | `getKeyRecursively` | parser.py | Input type, warning if input is not a dict, number of keys collected |
| 4 | `getValuesRecursively` | parser.py | Input type, number of values yielded, traceback on failure |
| 5 | `checkIfValidK8SYaml` | parser.py | File path, documents loaded, forbidden keywords found, presence of `apiVersion`/`kind`, final verdict |
| 6 | `getValsFromKey` | parser.py | Target key name and number of matches (not the matched values) |
| 7 | `isValidUserName` | scanner.py | Input type and length, whether a forbidden pattern matched, result |
| 8 | `isValidPasswordName` | scanner.py | Input type and length, whether a forbidden pattern matched, result |
| 9 | `checkIfValidSecret` | scanner.py | Input type and length, result, and which rule decided it (non-string / placeholder value / too short / valid) |
| 10 | `constructHelmString` | graphtaint.py | Input type, error when the input isn't a 3-item tuple or its parts aren't strings, resulting Helm key path |

### Design

We wanted to ensure that no sensisitve data would be in the logs as several of these moethods ahndle ussernames, passwords,
and secrets. Writing those values to a log file would create a securty risk that KubeSec isn't meant to detect. 
Thus, logs only record types, lengths, key names, and decisions. 

Recursive Methods log only at the top level. `keyMiner`, `getValuesRecursively` and `getValsFromKey` gained an optional 
`_top` parameter, and `getKeyRecursively` uses its existing `depth_` parameter. 

### Continuous Integration
We added a new workflow to the GitHub Actions CI pipeline called `forensics.yml`. This workflow runs the fuzz.py script,
which tests the 10 modified methods and generates a forensics.log

### Results
In the CI run, every method was called with a variety of inputs, and the forensics.log file was generated. The log file
contains information about the inputs, decisions, and any errors encountered during execution. This allows us to trace 
back the execution flow and understand how each method behaved under different conditions.

### Lessons Learned

**Fuzzing and forensics support each other.**

Our first version of the logging was missing one import (`from forensics_logger import describe`). The next fuzz run 
immediately reported a `NameError` in all 10 methods, and `forensics.log` showed only one entry before the crash. 
Together, the report and the log pinpointed the problem within minutes.

**Logging can leak data if you're not careful.**
The obivous approach is to log the arguments. For a security scanner, this would write secrets into a plain-text file.
Summarizing the inputs instead of reporting them was an important piece to our design to maintain security. 

**Recursion needs a logging strategy.** 
Logging inside of a recursive function makes the log unreadable . Logging only at the top level kept it useful.

**Configuration details matter.**
A .gitignore placed in a subfolder does not apply to files created in the repo root, and CI only keeps fiels that are
clearly listed as artifacts. 


