"""Bounded binary pipe frames and owned subprocess lifetime; no application protocol."""
import os
import selectors
import signal
import subprocess
import time


def refused():
    raise RuntimeError('Bounded channel unavailable; diagnostics withheld')


class Frames:
    def __init__(self, reader, writer, deadline, *, stderr=None, frame_limit=32768, output_limit=65536):
        self.reader, self.writer, self.stderr = reader, writer, stderr
        self.deadline, self.frame_limit, self.output_limit = deadline, frame_limit, output_limit
        self.buffer = bytearray()
        self.output_bytes = self.stderr_bytes = 0
        self.eof, self.error_eof = False, stderr is None
        self.selector = selectors.DefaultSelector()
        for stream, label in ((reader, 'reader'), (stderr, 'stderr')):
            if stream is not None:
                os.set_blocking(stream.fileno(), False)
                self.selector.register(stream, selectors.EVENT_READ, label)
        os.set_blocking(writer.fileno(), False)

    def remaining(self):
        value = self.deadline - time.monotonic()
        if value <= 0: refused()
        return value

    def _poll(self, *, writing=False, immediate=False):
        self.remaining()
        if writing:
            self.selector.register(self.writer, selectors.EVENT_WRITE, 'writer')
        writable = False
        try:
            events = self.selector.select(0 if immediate else self.remaining())
            if not events and not immediate: refused()
            for key, _ in events:
                if key.data == 'writer':
                    writable = True
                    continue
                try:
                    chunk = os.read(key.fileobj.fileno(), min(4096, self.output_limit - self.output_bytes + 1))
                except BlockingIOError:
                    continue
                if not chunk:
                    self.selector.unregister(key.fileobj)
                    if key.data == 'reader': self.eof = True
                    else: self.error_eof = True
                    continue
                self.output_bytes += len(chunk)
                if self.output_bytes > self.output_limit: refused()
                if key.data == 'stderr':
                    self.stderr_bytes += len(chunk)
                else:
                    self.buffer.extend(chunk)
                    first = self.buffer.find(b'\n')
                    if (first < 0 and len(self.buffer) > self.frame_limit) or first > self.frame_limit:
                        refused()
            return writable, bool(events)
        finally:
            if writing:
                self.selector.unregister(self.writer)

    def read_frame(self, *, allow_eof=False):
        while b'\n' not in self.buffer:
            if len(self.buffer) > self.frame_limit: refused()
            if self.eof:
                if allow_eof and not self.buffer: return None
                refused()
            self._poll()
        raw, _, rest = self.buffer.partition(b'\n')
        self.buffer = bytearray(rest)
        if not raw or len(raw) > self.frame_limit: refused()
        return bytes(raw)

    def no_pending(self):
        while self._poll(immediate=True)[1]:
            pass
        if self.buffer or self.stderr_bytes or self.eof: refused()

    def write_frame(self, raw):
        if not isinstance(raw, bytes) or not raw or len(raw) > self.frame_limit or b'\n' in raw:
            refused()
        pending = memoryview(raw + b'\n')
        try:
            while pending:
                if not self._poll(writing=True)[0]: continue
                try:
                    written = os.write(self.writer.fileno(), pending[:4096])
                except BlockingIOError:
                    continue
                if written <= 0: refused()
                pending = pending[written:]
        except (BrokenPipeError, OSError):
            refused()

    def require_eof(self):
        while not self.eof or not self.error_eof:
            self._poll()
        if self.buffer or self.stderr_bytes: refused()

    def close(self):
        self.selector.close()


class PipeChannel(Frames):
    def __init__(self, process, deadline, *, frame_limit=32768, output_limit=65536):
        self.process, self.finished = process, False
        super().__init__(process.stdout, process.stdin, deadline, stderr=process.stderr,
                         frame_limit=frame_limit, output_limit=output_limit)

    def close_input(self):
        if not self.writer.closed: self.writer.close()

    def finish(self):
        self.close_input()
        self.require_eof()
        # Keep the leader unreaped until its owned group is closed, preventing PID reuse.
        while os.waitid(os.P_PID, self.process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is None:
            time.sleep(min(.01, self.remaining()))
        try: os.killpg(self.process.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        try:
            status = self.process.wait(timeout=self.remaining())
        except subprocess.TimeoutExpired:
            refused()
        self.finished = True
        if status: refused()

    def close(self):
        if not self.finished:
            # start_new_session belongs to the factory; never signal another process group.
            try: os.killpg(self.process.pid, signal.SIGKILL)
            except ProcessLookupError: pass
        self.close_input()
        try:
            self.process.wait(timeout=1)
        except subprocess.TimeoutExpired:
            refused()
        finally:
            for stream in (self.process.stdout, self.process.stderr): stream.close()
            super().close()

    def __enter__(self):
        return self

    def __exit__(self, kind, value, trace):
        self.close()
