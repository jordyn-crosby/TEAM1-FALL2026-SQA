'''
Basic random fuzzer for 10 KubeSec (SLI-KUBE) methods.
Run: python fuzz.py   (from the repo root)
Any exception a method raises on junk input is logged as a possible bug.
'''
import os
import random
import string
import sys
import tempfile
import traceback

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), 'KubeSec-master'))
import parser  # noqa: E402  (KubeSec's own parser.py, not the stdlib one)
import scanner  # noqa: E402
import graphtaint  # noqa: E402

ITERATIONS = 200
random.seed(int(os.environ.get('FUZZ_SEED', '5710')))


def rand_str(n=None):
    n = random.randint(0, 40) if n is None else n
    return ''.join(random.choice(string.printable) for _ in range(n))


def rand_value(depth=0):
    choices = [None, True, 0, -1, 2**63, 3.14, float('nan'), '', rand_str(), b'\x00\xff', [], {}]
    if depth < 3:
        choices += [[rand_value(depth + 1) for _ in range(3)],
                    {rand_str(5): rand_value(depth + 1) for _ in range(3)}]
    return random.choice(choices)


def rand_file():
    # file with random (often invalid) YAML content
    f = tempfile.NamedTemporaryFile('w', suffix='.yaml', delete=False)
    f.write(random.choice([rand_str(200), 'a: [1, 2\n', 'key: value\n---\n- x\n', '', '{{ .Values.x }}\n']))
    f.close()
    return f.name


TARGETS = {
    'parser.checkIfWeirdYAML': lambda: parser.checkIfWeirdYAML(rand_value()),
    'parser.keyMiner': lambda: parser.keyMiner(rand_value(), rand_value()),
    'parser.getKeyRecursively': lambda: parser.getKeyRecursively(rand_value(), []),
    'parser.getValuesRecursively': lambda: list(parser.getValuesRecursively(rand_value())),
    'parser.getValsFromKey': lambda: parser.getValsFromKey(rand_value(), rand_value(), []),
    'parser.checkIfValidK8SYaml': lambda: parser.checkIfValidK8SYaml(rand_file()),
    'scanner.isValidUserName': lambda: scanner.isValidUserName(rand_value()),
    'scanner.isValidPasswordName': lambda: scanner.isValidPasswordName(rand_value()),
    'scanner.checkIfValidSecret': lambda: scanner.checkIfValidSecret(rand_value()),
    'graphtaint.constructHelmString': lambda: graphtaint.constructHelmString(rand_value()),
}


def main():
    bugs = {}
    for name, call in TARGETS.items():
        for _ in range(ITERATIONS):
            try:
                call()
            except Exception as e:
                key = (name, type(e).__name__, str(e)[:80])
                if key not in bugs:
                    bugs[key] = traceback.format_exc(limit=2)
    with open('fuzz_report.txt', 'w') as out:
        for (name, etype, msg), tb in bugs.items():
            line = f'BUG {name}: {etype}: {msg}'
            print(line)
            out.write(line + '\n' + tb + '\n')
    print(f'\nFuzzed {len(TARGETS)} methods x {ITERATIONS} inputs, {len(bugs)} unique crashes. See fuzz_report.txt')


if __name__ == '__main__':
    main()
