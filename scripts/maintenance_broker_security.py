"""Bound only the existing daily-security CLI capture; never retry or mutate Docker."""
import os
import subprocess
import threading
import time

REQUEST_LIMIT = 65536
REPORT_LIMIT = 4194304
TIMEOUT = 330
FAILURE = 'Trusted daily application check unavailable'


def read_daily_security(argv, payload):
    """One local CLI, bounded stdout and deadline; CLI reap is not daemon cleanup."""
    if type(payload) is not bytes or len(payload) > REQUEST_LIMIT:
        raise ValueError(FAILURE)
    process = None
    reader = writer = None
    done = threading.Event()
    sent = threading.Event()
    failed = threading.Event()
    chunks = []
    result = None
    unavailable = False
    try:
        deadline = time.monotonic() + TIMEOUT
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, shell=False, bufsize=0)

        def capture():
            size = 0
            try:
                while raw := os.read(process.stdout.fileno(), 65536):
                    size += len(raw)
                    if size > REPORT_LIMIT:
                        failed.set()
                        break
                    chunks.append(raw)
            except BaseException:
                failed.set()
            finally:
                done.set()

        def send():
            try:
                remaining = memoryview(payload)
                while remaining:
                    if time.monotonic() >= deadline: raise ValueError(FAILURE)
                    count = process.stdin.write(remaining)
                    if type(count) is not int or count <= 0: raise ValueError(FAILURE)
                    remaining = remaining[count:]
            except BaseException:
                failed.set()
            finally:
                try: process.stdin.close()
                except BaseException: failed.set()
                sent.set()

        reader = threading.Thread(target=capture, daemon=True)
        writer = threading.Thread(target=send, daemon=True)
        reader.start()
        writer.start()
        while not (done.is_set() and sent.is_set()):
            if failed.is_set() or time.monotonic() >= deadline:
                raise ValueError(FAILURE)
            failed.wait(.01)
        if failed.is_set() or time.monotonic() >= deadline:
            raise ValueError(FAILURE)
        code = process.wait(timeout=max(.001, deadline - time.monotonic()))
        if type(code) is not int or code != 0:
            raise ValueError(FAILURE)
        result = b''.join(chunks)
    except BaseException:
        unavailable = True
    finally:
        if process is not None:
            running = True
            try: running = process.poll() is None
            except BaseException: unavailable = True
            if running:
                try: process.kill()
                except BaseException: unavailable = True
            try:
                if type(process.wait(timeout=5)) is not int: unavailable = True
            except BaseException: unavailable = True
            for thread in (reader, writer):
                if thread is not None:
                    try:
                        thread.join(timeout=.1)
                        if thread.is_alive(): unavailable = True
                    except BaseException: unavailable = True
            # Unbuffered pipes avoid a BufferedReader lock during read/write.
            for pipe in (process.stdout, process.stdin):
                try: pipe.close()
                except BaseException: unavailable = True
    if unavailable or result is None:
        # No daemon-owned container stop/retry is inferred from a lost local CLI.
        raise ValueError(FAILURE) from None
    return result
