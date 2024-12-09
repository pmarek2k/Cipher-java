package com.pmarek.cipher.cipher;

import javax.crypto.spec.IvParameterSpec;
import java.security.SecureRandom;

public class CipherUtils {
    private static final IvParameterSpec ivSpec = generateIv();
    private static final IvParameterSpec ivSpecTripleDes = generateIvTripleDes();

    public static IvParameterSpec getIv() {
        return ivSpec;
    }

    public static IvParameterSpec getIvTripleDes() {
        return ivSpecTripleDes;
    }

    private static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    private static IvParameterSpec generateIvTripleDes() {
        byte[] iv = new byte[8];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
}
