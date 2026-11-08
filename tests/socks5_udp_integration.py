#!/usr/bin/env python3
"""Bounded, local-only integration test of the real nsjail NSTUN SOCKS5 path.

Run in a privileged disposable Docker container with network=none. A loopback
SOCKS5 fixture deliberately sends just one byte of its two-byte greeting reply.
Measure CPU of the *actual nsjail process*, not a copied parser implementation.
"""
import argparse
import json
import os
import signal
import socket
import stat
import subprocess
import threading
import time

CHILD_CODE = (
    "import socket,time\n"
    "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)\n"
    "s.sendto(b'probe',('198.51.100.15',40000))\n"
    "time.sleep(4)\n"
)


def ticks(pid):
    # /proc/<pid>/stat may contain spaces in comm; use the last ')' as delimiter.
    with open("/proc/%d/stat" % pid, encoding="ascii") as f:
        tail = f.read().rsplit(")", 1)[1].split()
    return int(tail[11]) + int(tail[12])


def ensure_tun():
    path = "/dev/net/tun"
    os.makedirs("/dev/net", exist_ok=True)
    if not os.path.exists(path):
        os.mknod(path, stat.S_IFCHR | 0o600, os.makedev(10, 200))
    if not stat.S_ISCHR(os.stat(path).st_mode):
        raise RuntimeError("No usable character device at /dev/net/tun")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--expect", choices=("busy", "quiet"), required=True)
    args = parser.parse_args()
    ensure_tun()
    errors = []
    received = threading.Event()
    listening = threading.Event()

    def proxy():
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
                server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                server.bind(("127.0.0.1", 1080))
                server.listen(1)
                server.settimeout(9)
                listening.set()
                conn, _ = server.accept()
                with conn:
                    conn.settimeout(4)
                    greeting = bytearray()
                    while len(greeting) < 3:
                        chunk = conn.recv(3 - len(greeting))
                        if not chunk:
                            raise RuntimeError("SOCKS5 greeting ended early")
                        greeting.extend(chunk)
                    if bytes(greeting) != b"\x05\x01\x00":
                        raise RuntimeError("Unexpected SOCKS5 client greeting: %r" % greeting)
                    conn.sendall(b"\x05")  # Incomplete: must NOT cause level-trigger spin.
                    received.set()
                    time.sleep(2.5)  # Hold socket open throughout CPU sampling.
        except Exception as exc:
            errors.append(str(exc))
            listening.set()
            received.set()

    thread = threading.Thread(target=proxy, daemon=True)
    thread.start()
    if not listening.wait(3):
        raise RuntimeError("Local SOCKS5 fixture did not start")
    if errors:
        raise RuntimeError("SOCKS5 fixture: %s" % errors[0])

    # The checked-in SOCKS5 config hardcodes Bash as exec_bin. The "--"
    # arguments do NOT override it: Bash treats the following argument as a
    # script pathname. Generate a local test-only config with Python exec_bin.
    with open("tests/socks5.cfg", encoding="utf-8") as template_file:
        template = template_file.read()
    marker = "\nexec_bin {"
    at = template.rfind(marker)
    if at < 0:
        raise RuntimeError("Could not locate exec_bin in fixture config")
    child_inline = (
        "import socket,time;"
        "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
        "s.sendto(b'probe',('198.51.100.15',40000));"
        "time.sleep(4)"
    )
    config = template[:at] + (
        '\nexec_bin {\n  path: "/usr/bin/python3"\n'
        '  arg: "-c"\n  arg: ' + json.dumps(child_inline) + '\n}\n'
    )
    config_path = "/tmp/nsjail-socks5-cpu.cfg"
    with open(config_path, "w", encoding="utf-8") as test_config:
        test_config.write(config)
    command = ["/bin/nsjail", "-C", config_path]
    with open("/tmp/nsjail-socks5-integration.log", "w", encoding="utf-8") as log:
        proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT,
                                start_new_session=True)
        try:
            if not received.wait(10) or errors:
                raise RuntimeError("SOCKS5 handshake not reached: %s" % errors)
            if proc.poll() is not None:
                raise RuntimeError("nsjail terminated before sampling")
            start = ticks(proc.pid)
            time.sleep(0.85)
            end = ticks(proc.pid)
            delta = end - start
            hertz = os.sysconf("SC_CLK_TCK")
            fraction = delta / (hertz * 0.85)
            print("REAL_NSJAIL_CPU_TICKS=%d CPU_CORE_FRACTION=%.3f EXPECT=%s" %
                  (delta, fraction, args.expect), flush=True)
            if args.expect == "busy":
                if fraction < 0.25:
                    raise AssertionError("Original code did not reproduce high CPU")
            else:
                if fraction > 0.12:
                    raise AssertionError("Patched code still consumes excessive CPU")
            print("PASS: real nsjail + NSTUN + fake SOCKS5 partial response", flush=True)
        except Exception:
            log.flush()
            with open("/tmp/nsjail-socks5-integration.log", encoding="utf-8",
                      errors="replace") as output:
                print("NSTUN_LOG_BEGIN\n%s\nNSTUN_LOG_END" % output.read()[-9000:],
                      flush=True)
            raise
        finally:
            if proc.poll() is None:
                os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=3)


if __name__ == "__main__":
    main()
