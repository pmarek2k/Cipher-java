package com.pmarek.cipher.cipher;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

@Service
@RequiredArgsConstructor
public class TripleDES {

    private static final String algorithmName = "DESede";

    public SecretKey generateKey() throws NoSuchAlgorithmException {
        return KeyGenerator.getInstance(algorithmName).generateKey();
    }

    public byte[] encrypt(SecretKey key, String data, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(data.getBytes());
    }

    public String decrypt(SecretKey key, byte[] encryptedData, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        return new String(cipher.doFinal(encryptedData));
    }

}
