
"""
Experimental Siglent SDS1202X-E ONC RPC client.

Based on observed traffic from:
  Firmware:   1.3.26
  EasyScopeX: V100R001B02D01P22

WARNING:
- Experimental protocol reconstruction, not a validated driver.
- Test on an isolated instrument LAN.
- Procedure 25 and session setup need validation.
- No waveform decoder is implemented here.
"""

import socket
import struct
import ipaddress
import itertools


RPC_PROGRAM = 395183       # 0x607AF
RPC_VERSION = 1
SCOPE_PORT = 912
CALLBACK_PORT = 738


def pad4(data: bytes) -> bytes:
    return data + b"\x00" * (-len(data) % 4)


def xdr_string(value: str) -> bytes:
    raw = value.encode("ascii")
    return struct.pack("!I", len(raw)) + pad4(raw)


def recv_exact(sock, size):
    """Read exactly size bytes, even when TCP splits the data."""
    chunks = []
    remaining = size

    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Connection closed during RPC reply")
        chunks.append(chunk)
        remaining -= len(chunk)

    return b"".join(chunks)


def recv_rpc_record(sock) -> bytes:
    """Read an ONC RPC record, including fragmented records."""
    fragments = []

    while True:
        marker = struct.unpack("!I", recv_exact(sock, 4))[0]
        final_fragment = bool(marker & 0x80000000)
        length = marker & 0x7FFFFFFF

        if length > 64 * 1024 * 1024:
            raise ValueError(f"Unreasonable RPC fragment length: {length}")

        fragments.append(recv_exact(sock, length))

        if final_fragment:
            return b"".join(fragments)


def parse_rpc_reply(record: bytes, expected_xid: int) -> bytes:
    """Validate the standard RPC reply header and return its result bytes."""
    if len(record) < 24:
        raise ValueError(f"RPC reply too short: {len(record)} bytes")

    xid, msg_type, reply_stat = struct.unpack("!III", record[:12])

    if xid != expected_xid:
        raise ValueError(
            f"Transaction ID mismatch: expected {expected_xid:#x}, "
            f"received {xid:#x}"
        )

    if msg_type != 1:
        raise ValueError(f"Expected RPC reply, message type was {msg_type}")

    if reply_stat != 0:
        raise RuntimeError(f"RPC message rejected: reply_stat={reply_stat}")

    # Reply verifier: flavor, length, and padded opaque data.
    offset = 12
    verifier_flavor, verifier_len = struct.unpack(
        "!II", record[offset:offset + 8]
    )
    offset += 8 + ((verifier_len + 3) // 4) * 4

    if offset + 4 > len(record):
        raise ValueError("Truncated RPC reply verifier")

    accept_stat = struct.unpack("!I", record[offset:offset + 4])[0]
    offset += 4

    if accept_stat != 0:
        raise RuntimeError(f"RPC call not accepted: accept_stat={accept_stat}")

    return record[offset:]


def find_printable_xdr_string(data: bytes):
    """
    Heuristic for text responses only.
    Does not decode binary waveform payloads or establish the full
    Siglent response schema.
    """
    candidates = []

    for offset in range(0, len(data) - 3, 4):
        length = struct.unpack("!I", data[offset:offset + 4])[0]
        start = offset + 4
        end = start + length

        if not 0 < length <= 65536 or end > len(data):
            continue

        raw = data[start:end]
        printable = sum(
            b in (9, 10, 13) or 32 <= b <= 126 for b in raw
        )

        if printable / len(raw) >= 0.90:
            candidates.append(raw)

    if not candidates:
        return None

    return max(candidates, key=len).decode("ascii", errors="replace").strip()


class SiglentRPC:
    def __init__(self, host: str, port: int = SCOPE_PORT,
                 timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.sock = None
        self.xids = itertools.count(0x71000001)

    def connect(self):
        self.sock = socket.create_connection(
            (self.host, self.port), timeout=self.timeout
        )
        self.sock.settimeout(self.timeout)
        print("Connected:", self.sock.getsockname(), "->",
              self.sock.getpeername())

    def close(self):
        if self.sock:
            self.sock.close()
            self.sock = None

    def rpc_call(self, procedure: int, arguments: bytes = b"") -> bytes:
        if self.sock is None:
            raise RuntimeError("Not connected")

        xid = next(self.xids) & 0xFFFFFFFF

        # ONC RPC call header:
        # xid, CALL, RPC version 2, program, program version, procedure,
        # credential flavor/length, verifier flavor/length.
        header = struct.pack(
            "!10I",
            xid, 0, 2,
            RPC_PROGRAM, RPC_VERSION, procedure,
            0, 0, 0, 0
        )

        message = header + arguments

        # TCP record marker: final fragment bit + message length.
        marker = 0x80000000 | len(message)
        self.sock.sendall(struct.pack("!I", marker) + message)

        record = recv_rpc_record(self.sock)
        return parse_rpc_reply(record, xid)

    def initialize(self, register_callback=True):
        """
        Reproduce the observed initial calls.
        Validate this sequence against a fresh capture before relying on it.
        """
        # Procedure 10: observed arguments include two zero integers,
        # timeout 2000, and the XDR string "inst0".
        args10 = (
            struct.pack("!III", 0, 0, 2000)
            + xdr_string("inst0")
        )
        result10 = self.rpc_call(10, args10)
        print("Procedure 10 result:", result10.hex())

        if register_callback:
            # Procedure 25 arguments observed in the capture:
            # client IPv4 address, callback port 738,
            # program 395185 (0x607B1), version 1, zero.
            local_ip = self.sock.getsockname()[0]
            ip_value = int(ipaddress.IPv4Address(local_ip))

            args25 = struct.pack(
                "!IIIII",
                ip_value,
                CALLBACK_PORT,
                395185,
                1,
                0
            )
            result25 = self.rpc_call(25, args25)
            print("Procedure 25 result:", result25.hex())

    def execute(self, command: str, max_bytes=16384,
                command_timeout_ms=2000, read_timeout_ms=2000):
        """
        Submit a SCPI command using observed procedure 11, then retrieve
        the result using observed procedure 12.

        The argument layouts are reconstructed from the capture and
        remain subject to verification.
        """
        if not command.endswith("\n"):
            command += "\n"

        # Observed procedure 11 argument layout:
        # uint64 timeout, uint32 zero, uint32 value 8, XDR string.
        args11 = (
            struct.pack("!QII", command_timeout_ms, 0, 8)
            + xdr_string(command)
        )
        result11 = self.rpc_call(11, args11)

        # Observed procedure 12 argument layout:
        # uint64 maximum response size, followed by four uint32 fields.
        args12 = struct.pack(
            "!QIIII",
            max_bytes,
            read_timeout_ms,
            0, 0, 10
        )
        result12 = self.rpc_call(12, args12)

        return {
            "submit_result_raw": result11,
            "response_result_raw": result12,
            "text_candidate": find_printable_xdr_string(result12),
        }


if __name__ == "__main__":
    # Replace with the oscilloscope's actual IP address.
    SCOPE_IP = "192.168.2.117"

    scope = SiglentRPC(SCOPE_IP)

    try:
        scope.connect()

        # The captured session starts with these setup calls.
        scope.initialize(register_callback=True)

        # Begin with a read-only query.
        result = scope.execute("*IDN?")

        print("Submit result:", result["submit_result_raw"].hex())
        print("Raw response:", result["response_result_raw"].hex())
        print("Possible text response:", result["text_candidate"])

    except (OSError, ValueError, RuntimeError, ConnectionError) as exc:
        print("RPC test failed:", exc)

    finally:
        scope.close()
