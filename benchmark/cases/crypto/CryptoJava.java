// Cryptography in Java (JCA names).
import java.security.*;
import javax.crypto.Cipher;

class CryptoJava {
    void brokenToday() throws Exception {
        MessageDigest.getInstance("MD5"); // expect[PQC001]
        MessageDigest.getInstance("SHA-256"); // safe[PQC001]
        Cipher.getInstance("DES/CBC/PKCS5Padding"); // expect[PQC002]
        Cipher.getInstance("AES/ECB/PKCS5Padding"); // expect[PQC003]
        Cipher.getInstance("AES"); // expect[PQC003] Java's default "AES" means AES/ECB
        Cipher.getInstance("AES/GCM/NoPadding"); // safe[PQC003]
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA"); // expect[PQC012]
        kpg.initialize(1024); // expect[PQC004]
    }

    void migrationInventory() throws Exception {
        // "ECB" in an RSA transformation name is a JCA naming quirk: RSA has no ECB mode.
        Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"); // expect[PQC010] safe[PQC003]
        Signature.getInstance("SHA256withECDSA"); // expect[PQC013]
    }
}
