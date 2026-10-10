// Cryptography in Node.js and the Web Crypto API.
const crypto = require("crypto");
const tls = require("tls");
const { privateKeyToAccount } = require("viem/accounts");

function brokenToday(key, iv) {
  crypto.createHash("md5"); // expect[PQC001]
  crypto.createHash("sha256"); // safe[PQC001]
  crypto.createCipheriv("des-ede3-cbc", key, iv); // expect[PQC002]
  crypto.createCipheriv("aes-256-ecb", key, null); // expect[PQC003]
  crypto.createCipheriv("aes-256-gcm", key, iv); // safe[PQC002,PQC003]
  crypto.generateKeyPairSync("rsa", { modulusLength: 1024 }); // expect[PQC004,PQC012]
  tls.connect({ host: "example.com", minVersion: "TLSv1" }); // expect[PQC005]
  tls.connect({ host: "example.com", minVersion: "TLSv1.2" }); // safe[PQC005]
}

async function migrationInventory(pub, buf) {
  crypto.generateKeyPairSync("ed25519"); // expect[PQC013]
  crypto.createECDH("prime256v1"); // expect[PQC011]
  crypto.publicEncrypt(pub, buf); // expect[PQC010]
  await globalThis.crypto.subtle.generateKey({ name: "RSA-OAEP", modulusLength: 3072 }, true, ["encrypt"]); // expect[PQC010]
  await globalThis.crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey"]); // expect[PQC011]
  const account = privateKeyToAccount(process.env.AGENT_PK); // expect[PQC014]
  const restored = await ethers.Wallet.fromEncryptedJson(json, password); // miss[PQC014] also an Ethereum wallet key
  const balance = await client.getBalance({ address: account.address }); // safe[PQC014] reading chain data, no keys
  return account;
}

module.exports = { brokenToday, migrationInventory };
