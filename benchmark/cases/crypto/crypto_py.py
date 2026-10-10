# Cryptography in Python (cryptography, PyCryptodome, hashlib, ssl).
import hashlib
import ssl

from Crypto.Cipher import AES
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa  # safe[PQC010,PQC012,PQC013] an import isn't a use
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # safe[PQC013]
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey  # safe[PQC011]
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def broken_today(password, data, key, iv, file_bytes, body):
    hashlib.md5(password.encode())  # expect[PQC001] password hashing with MD5
    hashlib.sha1(data).hexdigest()  # expect[PQC001]
    hashlib.md5(file_bytes, usedforsecurity=False)  # safe[PQC001] declared non-security use
    etag = hashlib.md5(body).hexdigest()  # noisy[PQC001] cache ETag, not security
    hashlib.sha256(data)  # safe[PQC001]
    Cipher(algorithms.TripleDES(key), modes.CBC(iv))  # expect[PQC002]
    Cipher(algorithms.AES(key), modes.ECB())  # expect[PQC003]
    AES.new(key, AES.MODE_ECB)  # expect[PQC003]
    Cipher(algorithms.AES(key), modes.GCM(iv))  # safe[PQC002,PQC003]
    rsa.generate_private_key(public_exponent=65537, key_size=1024)  # expect[PQC004,PQC012]
    rsa.generate_private_key(public_exponent=65537, key_size=3072)  # expect[PQC012] safe[PQC004]
    ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # expect[PQC005]
    return etag


def tls(ctx):
    ctx.minimum_version = ssl.TLSVersion.TLSv1  # expect[PQC005]
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2  # safe[PQC005]


def migration_inventory(pub, msg, data, signing_key):
    pub.encrypt(msg, padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None))  # expect[PQC010]
    X25519PrivateKey.generate()  # expect[PQC011]
    signing_key.sign(data, ec.ECDSA(hashes.SHA256()))  # expect[PQC013]
    Ed25519PrivateKey.generate()  # expect[PQC013]


DES_NOTE = "DES was withdrawn as a standard in 2005"  # safe[PQC002] just text
