# atlas: ignore-file  (this file defines the rules, so it contains the patterns it looks for)
"""Quantum-vulnerable and weak cryptography, plus a crypto inventory.

Problem area 5 ("harvest now, decrypt later"). Every post-quantum migration
plan starts with the same step: find out where you use which algorithm.
This scanner does that discovery step for a codebase.

Risk ranking:
  * Key exchange / public-key encryption (RSA-OAEP, ECDH, DH, X25519) is the
    urgent part: traffic recorded today can be decrypted once a large quantum
    computer exists.
  * Signatures (ECDSA, Ed25519, RSA-PSS, secp256k1) can't be broken
    retroactively, but long-lived keys still need a migration plan.
  * Weak classical crypto (MD5, SHA-1, DES, RC4, ECB, short RSA keys, old TLS)
    is broken today, quantum or not.
"""

from __future__ import annotations

import re
from collections import defaultdict
from typing import Iterable

from ..models import Finding, Rule, Severity, SourceFile
from . import Scanner

C = "quantum"
SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".java", ".kt", ".rs", ".rb",
    ".php", ".cs", ".c", ".cc", ".cpp", ".h", ".swift", ".sol",
    ".conf", ".cfg", ".ini", ".yaml", ".yml", ".toml", ".json", ".tf", ".xml", ".properties",
    ".pem", ".crt", ".cer", ".pub",
}

PQC_FIX_KEX = ("Plan migration to a hybrid post-quantum key exchange (e.g. X25519MLKEM768 in TLS) or ML-KEM "
               "(FIPS 203). Make the algorithm configurable so it can be swapped.")
PQC_FIX_SIG = ("Inventory where these keys live and how long they must stay trusted; plan for ML-DSA (FIPS 204) "
               "or SLH-DSA (FIPS 205) for long-lived signing keys.")

# (rule, inventory label, regex)
CHECKS: list[tuple[Rule, str, str]] = [
    # --- broken today ---
    (Rule("PQC001", "Weak hash (MD5/SHA-1) used", Severity.MEDIUM, C,
          "Use SHA-256 or better; for passwords use argon2, scrypt or bcrypt.", "CWE-328"),
     "MD5/SHA-1",
     r"hashlib\.(?:md5|sha1)\s*\((?![^)\n]*usedforsecurity\s*=\s*False)|createHash\(\s*[\"'](?:md5|sha1)[\"']|"
     r"MessageDigest\.getInstance\(\s*\"(?:MD5|SHA-?1)\"|\b(?:md5|sha1)\.(?:New|Sum)\(|Digest::(?:MD5|SHA1)\b"),
    (Rule("PQC002", "Broken cipher (DES/3DES/RC4/Blowfish)", Severity.HIGH, C,
          "Use AES-256-GCM or ChaCha20-Poly1305.", "CWE-327"),
     "DES/3DES/RC4",
     r"algorithms\.(?:TripleDES|ARC4|Blowfish|IDEA)\b|\b(?:DES3?|ARC4|Blowfish)\.new\(|"
     r"createCipheriv\(\s*[\"'](?:des|des3|des-ede3|rc4|bf)[\w-]*[\"']|Cipher\.getInstance\(\s*\"(?:DES|DESede|RC4)"),
    (Rule("PQC003", "ECB block-cipher mode", Severity.HIGH, C,
          "ECB leaks patterns in your data. Use GCM.", "CWE-327"),
     "ECB mode",
     r"modes\.ECB\b|MODE_ECB\b|[\"']aes-\d{3}-ecb[\"']|/ECB/"),
    (Rule("PQC004", "RSA key shorter than 2048 bits", Severity.HIGH, C,
          "Use at least 3072-bit RSA now, and plan the post-quantum move.", "CWE-326"),
     "RSA < 2048",
     r"key_size\s*=\s*(?:512|768|1024)\b|modulusLength\s*:\s*(?:512|768|1024)\b|"
     r"rsa\.GenerateKey\([^,\n]+,\s*(?:512|768|1024)\)|initialize\(\s*(?:512|768|1024)\s*\)"),
    (Rule("PQC005", "Outdated TLS/SSL version allowed", Severity.MEDIUM, C,
          "Require TLS 1.2 minimum, ideally TLS 1.3 (which also enables hybrid PQ key exchange).", "CWE-326"),
     "TLS < 1.2",
     r"PROTOCOL_(?:SSLv2|SSLv3|TLSv1|TLSv1_1)\b|TLSVersion\.(?:TLSv1|TLSv1_1|SSLv3)\b|"
     r"minVersion\s*:\s*[\"']TLSv1(?:\.1)?[\"']|tls\.VersionTLS1[01]\b|ssl_protocols[^;\n]*\b(?:SSLv3|TLSv1|TLSv1\.1)\s"),

    # --- quantum: harvest-now-decrypt-later ---
    (Rule("PQC010", "RSA encryption/key transport (quantum-vulnerable)", Severity.MEDIUM, C, PQC_FIX_KEX, "CWE-327"),
     "RSA encryption",
     r"padding\.OAEP\b|PKCS1_OAEP|PKCS1_v1_5\.new|publicEncrypt\(|privateDecrypt\(|[\"']RSA-OAEP[\"']|"
     r"rsa\.Encrypt(?:OAEP|PKCS1v15)|Cipher\.getInstance\(\s*\"RSA"),
    (Rule("PQC011", "Classical key exchange (ECDH/DH/X25519, quantum-vulnerable)", Severity.MEDIUM, C,
          PQC_FIX_KEX, "CWE-327"),
     "ECDH/DH/X25519",
     r"\bec\.ECDH\b|\bX25519PrivateKey\b|\bX448PrivateKey\b|createECDH\(|createDiffieHellman\(|"
     r"\bdh\.generate_parameters\(|ecdh\.(?:P256|P384|P521|X25519)\(|KeyAgreement\.getInstance\(|"
     r"[\"']ECDH[\"']|nacl\.box\b|crypto_box_keypair"),
    (Rule("PQC012", "RSA key generation (quantum-vulnerable)", Severity.LOW, C, PQC_FIX_KEX, "CWE-327"),
     "RSA keys",
     r"rsa\.generate_private_key\(|RSA\.generate\(|generateKeyPair(?:Sync)?\(\s*[\"']rsa|rsa\.GenerateKey\(|"
     r"KeyPairGenerator\.getInstance\(\s*\"RSA\"|-----BEGIN RSA (?:PUBLIC|PRIVATE) KEY-----"),
    (Rule("PQC013", "Classical signature scheme (quantum-vulnerable)", Severity.LOW, C, PQC_FIX_SIG, "CWE-327"),
     "ECDSA/EdDSA/DSA",
     r"\bec\.ECDSA\(|\bEd25519PrivateKey\b|\bEd448PrivateKey\b|\bdsa\.generate_private_key\(|"
     r"\bpadding\.PSS\(|generateKeyPair(?:Sync)?\(\s*[\"'](?:ec|ed25519|ed448|dsa)[\"']|"
     r"ecdsa\.(?:Sign|GenerateKey)\(|\bed25519\.(?:Sign|GenerateKey)\(|SigningKey\.generate\(|"
     r"\balgorithms?\s*[:=]\s*\[?\s*[\"'](?:RS|ES|PS)(?:256|384|512)[\"']|[\"']EdDSA[\"']|Signature\.getInstance\(\s*\"\w*(?:ECDSA|RSA|DSA)"),
    (Rule("PQC014", "secp256k1 wallet keys (quantum-vulnerable signatures)", Severity.INFO, C,
          "Exposed public keys on-chain can't be rotated retroactively. Avoid address reuse and track your chain's "
          "PQ roadmap.", "CWE-327"),
     "secp256k1",
     r"\bsecp256k1\b|privateKeyToAccount\(|new\s+ethers\.Wallet\(|Wallet\.createRandom\(|Account\.from_key\("),
]

PQC_READY = re.compile(r"(?i)\bML-?KEM\b|\bKyber\d*\b|\bML-?DSA\b|\bDilithium\d?\b|\bSLH-?DSA\b|\bSPHINCS\+?|"
                       r"\bFalcon-?\d+\b|X25519MLKEM768|X25519Kyber768|\bliboqs\b|\boqs\.")

INVENTORY = Rule("PQC000", "Cryptography inventory", Severity.INFO, C,
                 "Use this list as the 'Discovery' step of a post-quantum migration plan.")

_compiled = [(rule, label, re.compile(rx)) for rule, label, rx in CHECKS]


class QuantumCryptoScanner(Scanner):
    name = "quantum"
    category = C
    rules = [INVENTORY] + [r for r, _, _ in CHECKS]

    def __init__(self) -> None:
        self.inventory: dict[str, set[str]] = defaultdict(set)

    def applies(self, src: SourceFile) -> bool:
        return src.suffix in SUFFIXES

    def scan(self, src: SourceFile) -> Iterable[Finding]:
        for rule, label, rx in _compiled:
            for m in rx.finditer(src.text):
                line, col = src.line_of(m.start())
                self.inventory[label].add(src.path)
                yield Finding(rule=rule, path=src.path, line=line, column=col, snippet=src.snippet(line))
        if PQC_READY.search(src.text):
            self.inventory["Post-quantum (ML-KEM/ML-DSA/…)"].add(src.path)

    def finish(self) -> Iterable[Finding]:
        if not self.inventory:
            return []
        summary = {label: sorted(paths) for label, paths in sorted(self.inventory.items())}
        parts = ", ".join(f"{k}: {len(v)} file(s)" for k, v in summary.items())
        self.inventory = defaultdict(set)  # reset so the scanner can be reused
        return [Finding(rule=INVENTORY, path=".", line=1, snippet=parts,
                        message=f"Crypto inventory: {parts}", extra={"inventory": summary})]
