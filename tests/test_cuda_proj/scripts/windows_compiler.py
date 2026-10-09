import os
from pathlib import Path
import subprocess
import sys


def main():
    mode, compiler = sys.argv[1:3]
    arguments = sys.argv[3:]
    if mode in ('version', 'old_version', 'bad_version'):
        print({
            'version': 'Cuda compilation tools, release 13.1, V13.1.0',
            'old_version': 'Cuda compilation tools, release 12.8, V12.8.0',
            'bad_version': 'not an NVCC version',
        }[mode])
        return 0
    if mode == 'no_output':
        return 0
    if mode in ('passthrough', 'no_ptx', 'empty_ptx'):
        if mode != 'passthrough' and '--ptx' in arguments:
            if mode == 'empty_ptx':
                Path(arguments[arguments.index('--output-file') + 1]).write_bytes(b'')
            return 0
        return subprocess.call([compiler, *arguments])
    if mode not in ('ptxas', 'partial_cubin', 'no_cubin', 'empty_cubin'):
        raise ValueError(f'unknown compiler fixture mode: {mode}')
    if '--version' in arguments:
        print('Cuda compilation tools, release 13.1, V13.1.0')
        return 0
    if mode == 'no_cubin':
        return 0
    output = Path(arguments[arguments.index('--output-file') + 1])
    output.write_bytes({
        'ptxas': b'fake cubin',
        'partial_cubin': b'partial cubin',
        'empty_cubin': b'',
    }[mode])
    if mode == 'partial_cubin':
        return 37
    if mode == 'ptxas':
        print(os.environ['DEEP_JIT_TEST_PTXAS_OUTPUT'])
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
