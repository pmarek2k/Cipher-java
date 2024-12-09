package com.pmarek.cipher.cipher;

import ch.qos.logback.core.joran.sanity.Pair;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.security.*;
import javax.crypto.Cipher;

@Service
@RequiredArgsConstructor
public class RSA {

    private static final String algorithmName = "RSA";

    public KeyPair generateKeys(int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(algorithmName);
        keyGen.initialize(keySize);
        return keyGen.generateKeyPair();
    }

    public byte[] encrypt(PublicKey publicKey, String data) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(data.getBytes());
    }

    public String decrypt(PrivateKey privateKey, byte[] encryptedData) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return new String(cipher.doFinal(encryptedData));
    }
}
