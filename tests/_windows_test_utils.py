import os
from pathlib import Path
import runpy
import subprocess
import sys
import uuid

import ntsecuritycon
import win32api
import win32con
import win32event
import win32job
import win32security


_jobs = {}


def popen(arguments, **kwargs):
    if Path(arguments[0]) != Path(sys.executable):
        raise ValueError('The Windows test launcher requires the active Python interpreter')
    job = win32job.CreateJobObject(None, 'Local\\DeepJIT-job-' + uuid.uuid4().hex)
    event = None
    process = None
    try:
        limits = win32job.QueryInformationJobObject(
            job, win32job.JobObjectExtendedLimitInformation)
        limits['BasicLimitInformation']['LimitFlags'] |= (
            win32job.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE)
        win32job.SetInformationJobObject(
            job, win32job.JobObjectExtendedLimitInformation, limits)
        event_name = 'Local\\DeepJIT-test-' + uuid.uuid4().hex
        event = win32event.CreateEvent(None, True, False, event_name)
        process = subprocess.Popen([
            arguments[0], str(Path(__file__).resolve()),
            event_name, str(os.getpid()), *arguments[1:],
        ], **kwargs)
        handle = win32api.OpenProcess(
            win32con.PROCESS_SET_QUOTA | win32con.PROCESS_TERMINATE,
            False, process.pid,
        )
        try:
            win32job.AssignProcessToJobObject(job, handle)
        finally:
            handle.Close()
        win32event.SetEvent(event)
        _jobs[process.pid] = (process, job, event)
        return process
    except BaseException:
        try:
            if process is not None:
                process.kill()
                process.wait(timeout=5)
        finally:
            try:
                if event is not None:
                    event.Close()
            finally:
                job.Close()
        raise


def unregister_process(process):
    entry = _jobs.pop(process.pid, None)
    if entry:
        _, job, event = entry
        try:
            job.Close()
        finally:
            event.Close()


def terminate_process(process):
    entry = _jobs.get(process.pid)
    if entry:
        win32job.TerminateJobObject(entry[1], 1)
    elif process.poll() is None:
        process.kill()
    try:
        process.communicate(timeout=5)
    finally:
        unregister_process(process)


def terminate_registered_processes():
    for process, _, _ in list(_jobs.values()):
        terminate_process(process)


def split_command(command):
    return win32api.CommandLineToArgv(command)


def deny_write_attributes(path):
    security = win32security.GetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION)
    original = security.GetSecurityDescriptorDacl()
    if original is None:
        raise RuntimeError('The cache marker fixture requires an existing DACL')
    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32con.TOKEN_QUERY)
    try:
        user = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    finally:
        token.Close()
    original.SetEntriesInAcl([{
        'AccessPermissions': ntsecuritycon.FILE_WRITE_ATTRIBUTES,
        'AccessMode': win32security.DENY_ACCESS,
        'Inheritance': win32security.NO_INHERITANCE,
        'Trustee': {
            'TrusteeForm': win32security.TRUSTEE_IS_SID,
            'TrusteeType': win32security.TRUSTEE_IS_USER,
            'Identifier': user,
        },
    }])
    win32security.SetNamedSecurityInfo(
        str(path), win32security.SE_FILE_OBJECT, win32security.DACL_SECURITY_INFORMATION,
        None, None, original, None)


def run_registered_script():
    # Do not run test code or spawn its descendants before job assignment.
    event_name, parent_pid, script, *arguments = sys.argv[1:]
    event = win32event.OpenEvent(win32con.SYNCHRONIZE, False, event_name)
    try:
        parent = win32api.OpenProcess(
            win32con.SYNCHRONIZE, False, int(parent_pid)
        )
        try:
            result = win32event.WaitForMultipleObjects([event, parent], False, 60000)
            if result != win32event.WAIT_OBJECT_0:
                raise RuntimeError('Parent exited or timed out before assigning the test job')
        finally:
            parent.Close()
    finally:
        event.Close()
    sys.argv = [script, *arguments]
    sys.path[0] = str(Path(script).resolve().parent)
    runpy.run_path(script, run_name='__main__')


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == '--readonly-marker':
        deny_write_attributes(sys.argv[2])
    else:
        run_registered_script()
