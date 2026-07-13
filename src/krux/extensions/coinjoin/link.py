# The MIT License (MIT)

# Copyright (c) 2021-2024 Krux contributors

# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:

# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.

# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
"""Framed byte link for CoinJoin remote signing.

Frames are 4-byte big-endian length + payload, both directions.

On device the link takes over UARTHS (the CH340 USB serial the console
lives on) as a machine.UART, which detaches the REPL's rx interrupt for
the session. On desktop (simulator) the link is a localhost TCP server so
the same host bridge can talk to either backend.
"""
import time

try:
    from machine import UART

    _ON_DEVICE = True
except ImportError:
    import socket

    _ON_DEVICE = False

TCP_PORT = 52123
UART_BAUDRATE = 115200
FRAME_MAX = 1024 * 1024
_INTERBYTE_TIMEOUT_MS = 5000
# Every frame starts with this magic so the reader can resync after line
# noise (e.g. the K210 boot console) instead of reading noise as a length.
MAGIC = b"KXJ1"


class LinkTimeout(Exception):
    """No complete frame arrived in time."""


class Link:
    """Framed link over UARTHS (device) or TCP (simulator)."""

    def __init__(self):
        self._uart = None
        self._server = None
        self._conn = None

    def open(self):
        """Claims the channel."""
        if _ON_DEVICE:
            try:
                import micropython

                micropython.kbd_intr(-1)
            except Exception:
                pass  # rx interrupt is ours anyway once the UART is claimed
            # ponytail: takes over the console UART; REPL stays detached
            # until reboot, which Krux never uses in production anyway
            self._uart = UART(UART.UARTHS, UART_BAUDRATE, read_buf_len=8192)
        else:
            self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server.bind(("127.0.0.1", TCP_PORT))
            self._server.listen(1)
            self._server.settimeout(0.05)

    def close(self):
        """Releases the channel."""
        if _ON_DEVICE:
            if self._uart:
                self._uart.deinit()
                self._uart = None
        else:
            for sock in (self._conn, self._server):
                if sock:
                    sock.close()
            self._conn = None
            self._server = None

    def _read_exact(self, num_bytes, first_timeout_ms):
        """Returns num_bytes from the channel, or None if nothing arrived
        before first_timeout_ms. Raises LinkTimeout on a stalled frame."""
        chunks = b""
        timeout_ms = first_timeout_ms
        # Device only: ticks_ms wraps, so track the budget with ticks_diff
        # rather than comparing absolute ticks. (ticks_* are MicroPython-only.)
        deadline = time.ticks_add(time.ticks_ms(), first_timeout_ms) if _ON_DEVICE else 0
        while len(chunks) < num_bytes:
            if _ON_DEVICE:
                data = self._uart.read(num_bytes - len(chunks))
                if data:
                    chunks += data
                    deadline = time.ticks_add(time.ticks_ms(), _INTERBYTE_TIMEOUT_MS)
                    continue
                if time.ticks_diff(deadline, time.ticks_ms()) <= 0:
                    if chunks:
                        raise LinkTimeout("frame stalled")
                    return None
                time.sleep_ms(5)
            else:
                if self._conn is None:
                    try:
                        self._conn, _ = self._server.accept()
                    except socket.timeout:
                        return None
                self._conn.settimeout(timeout_ms / 1000)
                try:
                    data = self._conn.recv(num_bytes - len(chunks))
                except socket.timeout:
                    if chunks:
                        raise LinkTimeout("frame stalled")
                    return None
                if not data:  # client disconnected; await the next one
                    self._conn.close()
                    self._conn = None
                    if chunks:
                        raise LinkTimeout("client disconnected mid-frame")
                    return None
                chunks += data
                timeout_ms = _INTERBYTE_TIMEOUT_MS
        return chunks

    def _sync_to_magic(self, first_timeout_ms):
        """Consumes bytes until MAGIC is seen. Returns True once synced, or
        False if nothing arrived in time (no frame starting)."""
        window = b""
        timeout_ms = first_timeout_ms
        while True:
            byte = self._read_exact(1, timeout_ms)
            if byte is None:
                return False
            window = (window + byte)[-len(MAGIC):]
            if window == MAGIC:
                return True
            timeout_ms = _INTERBYTE_TIMEOUT_MS

    def read_frame(self, timeout_ms=100):
        """Returns one frame payload, or None if no frame started in time."""
        if not self._sync_to_magic(timeout_ms):
            return None
        header = self._read_exact(4, _INTERBYTE_TIMEOUT_MS)
        if header is None:
            raise LinkTimeout("frame length missing")
        length = int.from_bytes(header, "big")
        if length > FRAME_MAX:
            raise ValueError("frame too large: %d" % length)
        if length == 0:
            return b""
        payload = self._read_exact(length, _INTERBYTE_TIMEOUT_MS)
        if payload is None:
            raise LinkTimeout("frame header without payload")
        return payload

    def write_frame(self, payload):
        """Writes one framed payload."""
        data = MAGIC + len(payload).to_bytes(4, "big") + payload
        if _ON_DEVICE:
            self._uart.write(data)
        else:
            if self._conn is None:
                raise LinkTimeout("no client connected")
            self._conn.sendall(data)
