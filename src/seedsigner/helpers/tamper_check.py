"""
The `.sse` container: SeedSigner's encrypted stage-2 rootfs.

A card that has been swapped cannot produce the verify words for a code it has
never seen, and cannot decrypt a payload it has no key for. That is the whole
mechanism. See docs/tamper_check.md for what it does and does not stop -- in
particular it does NOT stop an attacker who imaged your card before you typed
anything, and it is not a substitute for reflashing.

All cryptography comes from libsodium via PyNaCl. Nothing here implements a
primitive. The stage-1 unlocker in seedsigner-os should link libsodium (or
Monocypher) so that both sides run the same well-reviewed code rather than two
implementations that have to be argued equal.

Layout, little-endian, header is 66 bytes:

    magic       8   b"SSTC\\x01\\x00\\x00\\x00"
    kdf_id      1   1 = argon2id
    mem_kib     4   KDF memory cost in KiB
    time_cost   4   KDF ops limit
    lanes       1   KDF parallelism; libsodium fixes this at 1
    salt       16   random, per install (== argon2id SALTBYTES)
    nonce      24   random, per install (XChaCha20)
    ct_len      8   plaintext length; the body is ct_len + 16 bytes
    --
    body        N   XChaCha20-Poly1305(payload), ciphertext with tag appended

The entire header is passed as AEAD associated data, so the KDF parameters are
authenticated too: an attacker cannot weaken mem_kib on a stolen card and hand
it back without the tag failing.
"""
import hashlib
import hmac
import os
import struct

from nacl import bindings, exceptions, pwhash


MAGIC = b"SSTC\x01\x00\x00\x00"

KDF_ARGON2ID = 1

HEADER_FORMAT = "<8sBIIB16s24sQ"
HEADER_SIZE = struct.calcsize(HEADER_FORMAT)  # 66
SALT_SIZE = pwhash.argon2id.SALTBYTES  # 16
NONCE_SIZE = bindings.crypto_aead_xchacha20poly1305_ietf_NPUBBYTES  # 24
TAG_SIZE = bindings.crypto_aead_xchacha20poly1305_ietf_ABYTES  # 16
KEY_SIZE = bindings.crypto_aead_xchacha20poly1305_ietf_KEYBYTES  # 32

VERIFY_WORD_COUNT = 4
VERIFY_WORD_INFO = b"ss-tc-verify"

# Production parameters. 64 MiB sits well inside a 512 MB Pi Zero while staying
# expensive to brute-force, and lands just above libsodium's own INTERACTIVE
# profile for argon2id. NOT yet timed on real hardware -- treat as a proposal.
DEFAULT_MEM_KIB = 65536
DEFAULT_TIME_COST = 3
DEFAULT_LANES = 1


class TamperCheckError(Exception):
    pass


class ContainerFormatError(TamperCheckError):
    pass


class UnlockFailed(TamperCheckError):
    """
    The container did not authenticate.

    Deliberately does not distinguish "wrong code" from "payload was altered":
    the caller cannot tell them apart and neither should an attacker watching
    the screen.
    """
    pass


def normalize_code(code) -> bytes:
    """
    Encode an unlock code to the exact bytes the KDF sees.

    Restricted to printable ASCII on purpose. The stage-1 unlocker is a small C
    binary with no Unicode support, and a code that normalizes differently in
    the two implementations is an unrecoverable brick.
    """
    raw = code if isinstance(code, bytes) else code.encode("utf-8")
    if not raw:
        raise ValueError("unlock code must not be empty")
    if any(byte < 0x20 or byte > 0x7e for byte in raw):
        raise ValueError("unlock code must be printable ASCII")
    return raw


def derive_key(code, salt: bytes, kdf_id: int = KDF_ARGON2ID,
               mem_kib: int = DEFAULT_MEM_KIB, time_cost: int = DEFAULT_TIME_COST,
               lanes: int = DEFAULT_LANES) -> bytes:
    """Stretch the unlock code into the 32-byte container key."""
    password = normalize_code(code)
    if len(salt) != SALT_SIZE:
        raise ContainerFormatError("salt must be %d bytes" % SALT_SIZE)
    if kdf_id != KDF_ARGON2ID:
        raise ContainerFormatError("unknown kdf_id %r" % (kdf_id,))
    if lanes != 1:
        # libsodium's crypto_pwhash fixes argon2id parallelism at 1 and gives
        # no way to set it. Keep the field so the format can grow, but refuse
        # any value the C side could not reproduce.
        raise ContainerFormatError("libsodium argon2id requires lanes=1")

    try:
        return pwhash.argon2id.kdf(KEY_SIZE, password, salt,
                                   opslimit=time_cost, memlimit=mem_kib * 1024)
    except exceptions.CryptoError as exc:
        raise ContainerFormatError("KDF parameters rejected: %s" % exc)


def verify_words(key: bytes, wordlist=None, count: int = VERIFY_WORD_COUNT) -> list:
    """
    The words shown before anything is decrypted, so the user can walk away
    from a device that cannot produce them.

    Derived from the key rather than stored, so there is no separate blob for
    an attacker to lift, and they are automatically correct if and only if the
    code was.
    """
    if wordlist is None:
        from embit.wordlists.bip39 import WORDLIST as wordlist

    bits_per_word = (len(wordlist) - 1).bit_length()
    if 1 << bits_per_word != len(wordlist):
        raise ValueError("wordlist length must be a power of two")

    digest = hmac.new(key, VERIFY_WORD_INFO, hashlib.sha256).digest()
    if count * bits_per_word > len(digest) * 8:
        raise ValueError("wordlist too large for %d words of output" % count)

    pool = int.from_bytes(digest, "big")
    total_bits = len(digest) * 8
    words = []
    for i in range(count):
        shift = total_bits - (i + 1) * bits_per_word
        words.append(wordlist[(pool >> shift) & (len(wordlist) - 1)])
    return words


def pack_header(kdf_id: int, mem_kib: int, time_cost: int, lanes: int,
                salt: bytes, nonce: bytes, ct_len: int) -> bytes:
    return struct.pack(HEADER_FORMAT, MAGIC, kdf_id, mem_kib, time_cost,
                       lanes, salt, nonce, ct_len)


def unpack_header(blob: bytes) -> dict:
    if len(blob) < HEADER_SIZE:
        raise ContainerFormatError("truncated header")
    magic, kdf_id, mem_kib, time_cost, lanes, salt, nonce, ct_len = struct.unpack(
        HEADER_FORMAT, blob[:HEADER_SIZE]
    )
    if magic != MAGIC:
        raise ContainerFormatError("not an .sse container")
    return {
        "kdf_id": kdf_id, "mem_kib": mem_kib, "time_cost": time_cost,
        "lanes": lanes, "salt": salt, "nonce": nonce, "ct_len": ct_len,
    }


def seal(payload: bytes, code, kdf_id: int = KDF_ARGON2ID,
         mem_kib: int = DEFAULT_MEM_KIB, time_cost: int = DEFAULT_TIME_COST,
         lanes: int = DEFAULT_LANES, salt: bytes = None, nonce: bytes = None) -> bytes:
    """
    Build a container. `salt` and `nonce` are injectable for test vectors only;
    leave them None everywhere else so they come from os.urandom.
    """
    salt = os.urandom(SALT_SIZE) if salt is None else salt
    nonce = os.urandom(NONCE_SIZE) if nonce is None else nonce

    key = derive_key(code, salt, kdf_id, mem_kib, time_cost, lanes)
    header = pack_header(kdf_id, mem_kib, time_cost, lanes, salt, nonce, len(payload))
    body = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
        payload, header, nonce, key
    )
    return header + body


def unseal(blob: bytes, code) -> bytes:
    """
    Open a container, or raise UnlockFailed.

    NOTE: this holds the ciphertext and the plaintext in memory at once, which
    is exactly the peak-memory question flagged in the design memo. Resolve it
    before this format is frozen -- streaming would need per-chunk tags, and
    that is a format change, not an implementation detail.
    """
    fields = unpack_header(blob)
    body = blob[HEADER_SIZE:]
    if len(body) != fields["ct_len"] + TAG_SIZE:
        raise ContainerFormatError("container length does not match ct_len")

    key = derive_key(code, fields["salt"], fields["kdf_id"], fields["mem_kib"],
                     fields["time_cost"], fields["lanes"])
    try:
        return bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
            body, blob[:HEADER_SIZE], fields["nonce"], key
        )
    except exceptions.CryptoError:
        raise UnlockFailed("container did not authenticate")
