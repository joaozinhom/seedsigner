"""
Build, inspect and open `.sse` containers -- the encrypted stage-2 rootfs that
the SeedSigner bootloader code gate unlocks.

This is the reference implementation. All cryptography is libsodium via
PyNaCl; nothing here implements a primitive. The stage-1 C unlocker in
seedsigner-os has to reproduce the golden vector in `selftest` byte for byte.

tldr:
    python3 -m venv .venv && .venv/bin/pip install pynacl embit
    PYTHONPATH=src .venv/bin/python tools/sse.py selftest
    PYTHONPATH=src .venv/bin/python tools/sse.py seal rootfs.cpio.gz rootfs.sse
"""
import argparse
import getpass
import sys
import time

from seedsigner.helpers import tamper_check as tc




def _prompt(args, confirm=False):
    if args.code is not None:
        return args.code
    code = getpass.getpass("Unlock code: ")
    if confirm and code != getpass.getpass("Confirm code: "):
        sys.exit("Codes do not match.")
    return code


def _show_words(key):
    try:
        words = tc.verify_words(key)
    except ImportError:
        print("Verify words: (embit not installed -- pip install embit)")
        return
    print("Verify words: " + "  ".join(words))


def cmd_seal(args):
    payload = open(args.infile, "rb").read()
    started = time.time()
    blob = tc.seal(payload, _prompt(args, confirm=True),
                   mem_kib=args.mem_kib, time_cost=args.time_cost)
    open(args.outfile, "wb").write(blob)
    print("Sealed %s (%d bytes) -> %s (%d bytes) in %.1fs"
          % (args.infile, len(payload), args.outfile, len(blob), time.time() - started))
    fields = tc.unpack_header(blob)
    _show_words(tc.derive_key(_prompt(args), fields["salt"], fields["kdf_id"],
                              fields["mem_kib"], fields["time_cost"], fields["lanes"]))
    print("\nWrite these words down. The device shows them at every boot, before\n"
          "it decrypts anything. If they are ever wrong, treat the code as burned\n"
          "as well as the card: reflash AND choose a new code.")


def cmd_open(args):
    blob = open(args.infile, "rb").read()
    started = time.time()
    try:
        payload = tc.unseal(blob, _prompt(args))
    except tc.UnlockFailed:
        sys.exit("Did not authenticate: wrong code, or the payload was altered.")
    open(args.outfile, "wb").write(payload)
    print("Opened %s -> %s (%d bytes) in %.1fs"
          % (args.infile, args.outfile, len(payload), time.time() - started))


def cmd_info(args):
    fields = tc.unpack_header(open(args.infile, "rb").read())
    kdf = {tc.KDF_ARGON2ID: "argon2id"}.get(
        fields["kdf_id"], "unknown(%d)" % fields["kdf_id"])
    print("container : %s" % args.infile)
    print("kdf       : %s  mem=%d KiB  time=%d  lanes=%d"
          % (kdf, fields["mem_kib"], fields["time_cost"], fields["lanes"]))
    print("salt      : %s" % fields["salt"].hex())
    print("nonce     : %s" % fields["nonce"].hex())
    print("payload   : %d bytes" % fields["ct_len"])


def cmd_words(args):
    fields = tc.unpack_header(open(args.infile, "rb").read())
    _show_words(tc.derive_key(_prompt(args), fields["salt"], fields["kdf_id"],
                              fields["mem_kib"], fields["time_cost"], fields["lanes"]))


# A container built with fixed salt, nonce, code and payload. This is the
# vector the stage-1 C unlocker has to reproduce exactly.
VECTOR = dict(
    code="seedsigner",
    salt=bytes(range(16)),
    nonce=bytes(range(24)),
    mem_kib=8192,
    time_cost=1,
    payload=b"seedsigner stage 2 rootfs placeholder\n",
    key="ed8b0d12b27d3bc6f5b8e292c2071ee64f7e44a32080d7a58f3d4ff50fbd1bbd",
    sha256="47c9a26ae2a775a1b39d5ea42ede5d12df88d9a210049e7866ba6c7a51b3967f",
    words=["shop", "bounce", "ribbon", "exclude"],
)


def cmd_selftest(args):
    import hashlib
    import nacl

    failures = []

    def check(name, condition):
        print(("  PASS  " if condition else "  FAIL  ") + name)
        if not condition:
            failures.append(name)

    print("Backend")
    print("  libsodium via PyNaCl %s" % nacl.__version__)
    check("salt size matches argon2id SALTBYTES", tc.SALT_SIZE == 16)
    check("header is %d bytes" % tc.HEADER_SIZE, tc.HEADER_SIZE == 66)

    print("\nGolden vector (stage-1 C must reproduce this)")
    v = VECTOR
    kw = dict(mem_kib=v["mem_kib"], time_cost=v["time_cost"])
    blob = tc.seal(v["payload"], v["code"], salt=v["salt"], nonce=v["nonce"], **kw)
    key = tc.derive_key(v["code"], v["salt"], **kw)
    check("argon2id key         %s" % v["key"][:24] + "...", key.hex() == v["key"])
    check("container sha256     %s" % v["sha256"][:24] + "...",
          hashlib.sha256(blob).hexdigest() == v["sha256"])
    check("round trip", tc.unseal(blob, v["code"]) == v["payload"])

    print("\nRejections")

    def rejects(name, mutated, code=v["code"]):
        try:
            tc.unseal(mutated, code)
            check(name, False)
        except (tc.UnlockFailed, tc.ContainerFormatError):
            check(name, True)

    rejects("wrong code", blob, "seedsigne")
    flip = bytearray(blob)
    flip[tc.HEADER_SIZE + 10] ^= 0x01
    rejects("flipped ciphertext byte", bytes(flip))
    weakened = bytearray(blob)
    weakened[9:13] = (1024).to_bytes(4, "little")  # mem_kib 8192 -> 1024
    rejects("weakened KDF parameters", bytes(weakened))
    rejects("truncated container", blob[:-1])
    rejects("wrong magic", b"XXXX" + blob[4:])

    print("\nVerify words")
    try:
        wrong_key = tc.derive_key("seedsigne", v["salt"], **kw)
        check("right code -> %s" % " ".join(v["words"]),
              tc.verify_words(key) == v["words"])
        check("wrong code -> %s (differs)" % " ".join(tc.verify_words(wrong_key)),
              tc.verify_words(wrong_key) != v["words"])
    except ImportError:
        print("  SKIP  embit not installed")

    print("\n%d failure(s)" % len(failures) if failures else "\nAll checks passed.")
    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    def add_code(p):
        p.add_argument("--code", help="unlock code (omit to be prompted)")

    p = sub.add_parser("seal", help="encrypt a payload into a container")
    p.add_argument("infile"); p.add_argument("outfile"); add_code(p)
    p.add_argument("--mem-kib", type=int, default=tc.DEFAULT_MEM_KIB)
    p.add_argument("--time-cost", type=int, default=tc.DEFAULT_TIME_COST)
    p.set_defaults(func=cmd_seal)

    p = sub.add_parser("open", help="decrypt a container")
    p.add_argument("infile"); p.add_argument("outfile"); add_code(p)
    p.set_defaults(func=cmd_open)

    p = sub.add_parser("info", help="print a container's header")
    p.add_argument("infile")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("words", help="show the verify words for a container")
    p.add_argument("infile"); add_code(p)
    p.set_defaults(func=cmd_words)

    p = sub.add_parser("selftest", help="run test vectors and container checks")
    p.set_defaults(func=cmd_selftest)

    args = parser.parse_args()
    sys.exit(args.func(args) or 0)


if __name__ == "__main__":
    main()
