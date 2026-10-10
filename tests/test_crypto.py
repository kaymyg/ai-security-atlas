from conftest import ids


def test_weak_and_quantum_vulnerable_crypto(scan):
    py = "\n".join([
        "hashlib.md5(data)",
        "algorithms.TripleDES(key)",
        "modes.ECB()",
        "rsa.generate_private_key(public_exponent=65537, key_size=1024)",
        "padding.OAEP(mgf=m, algorithm=a, label=None)",
        "X25519PrivateKey.generate()",
        "ec.ECDSA(hashes.SHA256())",
        "ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)",
    ])
    found = ids(scan({"crypto.py": py}))
    for rule in ["PQC001", "PQC002", "PQC003", "PQC004", "PQC005", "PQC010", "PQC011", "PQC012", "PQC013"]:
        assert rule in found, rule


def test_md5_for_non_security_use_is_ok(scan):
    findings = scan({"cache.py": "key = hashlib.md5(url, usedforsecurity=False).hexdigest()\n"})
    assert "PQC001" not in ids(findings)


def test_inventory_summarises_algorithms(scan):
    findings = scan({
        "a.py": "rsa.generate_private_key(public_exponent=65537, key_size=4096)\n",
        "b.js": "crypto.createECDH('prime256v1')\n",
        "c.go": "kem := mlkem.GenerateKey768() // ML-KEM\n",
    })
    inv = next(f for f in findings if f.rule.id == "PQC000").extra["inventory"]
    assert inv["RSA keys"] == ["a.py"]
    assert inv["ECDH/DH/X25519"] == ["b.js"]
    assert "c.go" in inv["Post-quantum (ML-KEM/ML-DSA/…)"]


def test_docs_are_not_scanned_for_crypto(scan):
    assert scan({"README.md": "We use RSA-OAEP and ECDH. hashlib.md5() is bad.\n"}) == []
