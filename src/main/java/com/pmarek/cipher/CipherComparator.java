package com.pmarek.cipher;

import com.pmarek.cipher.cipher.AES;
import com.pmarek.cipher.cipher.CipherUtils;
import com.pmarek.cipher.cipher.RSA;
import com.pmarek.cipher.cipher.TripleDES;
import jakarta.annotation.PostConstruct;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.util.StopWatch;

import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import java.io.FileWriter;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.util.ArrayList;
import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class CipherComparator {

    private final AES aes;
    private final RSA rsa;
    private final TripleDES tripleDES;

    @PostConstruct
    public void compareAlgorithms() throws Exception {
        List<String[]> resultsGeneration = new ArrayList<>();
        resultsGeneration.add(new String[]{"Algorithm", "Operation", "Data Size", "Time (ms)"});

        compareKeyGenerationTimes(resultsGeneration);
        saveResultsToCSV(resultsGeneration, "keysGeneration");

        List<String[]> resultsEncDec = new ArrayList<>();
        resultsEncDec.add(new String[]{"Algorithm", "Operation", "Data Size", "Time (ms)"});
        compareEncryptionDecryptionTimes(resultsEncDec);
        saveResultsToCSV(resultsEncDec, "ecnryptionDecrytion");
    }

    private void compareKeyGenerationTimes(List<String[]> results) throws Exception {
        int[] userCounts = {1, 10, 100, 1000};
        for (int users : userCounts) {
            log.info("Generating key for AES - {}", users);
            results.add(new String[]{ "AES", "Key Generation", String.valueOf(users), String.valueOf(measureTime(() -> {
                try {
                    for (int i = 0; i < users; i++) aes.generateKey();
                } catch (Exception e) { e.printStackTrace(); }
            }))});

            log.info("Generating key for RSA - {}", users);
            results.add(new String[]{ "RSA", "Key Generation", String.valueOf(users), String.valueOf(measureTime(() -> {
                try {
                    for (int i = 0; i < users; i++) rsa.generateKeys(2048);
                } catch (Exception e) { e.printStackTrace(); }
            }))});

            log.info("Generating key for 3DES - {}", users);
            results.add(new String[]{ "3DES", "Key Generation", String.valueOf(users), String.valueOf(measureTime(() -> {
                try {
                    for (int i = 0; i < users; i++) tripleDES.generateKey();
                } catch (Exception e) { e.printStackTrace(); }
            }))});
        }
    }

    private void compareEncryptionDecryptionTimes(List<String[]> results) throws Exception {
        int[] dataSizes = {1, 10, 100, 10000, 100000, 1000000};
        String data = "A".repeat(1000000);

        for (int size : dataSizes) {
            String inputData = data.substring(0, size);

            Key aesKey = aes.generateKey();
            SecretKey tripleDESKey = tripleDES.generateKey();
            KeyPair rsaKeys = rsa.generateKeys(4096);

            IvParameterSpec iv = CipherUtils.getIv();
            IvParameterSpec ivTripleDes = CipherUtils.getIvTripleDes();

            log.info("Encryption AES - {}", size);
            results.add(new String[]{"AES", "Encryption", String.valueOf(size), String.valueOf(measureTime(() -> {
                try { aes.encrypt(aesKey, inputData, iv); } catch (Exception e) { e.printStackTrace(); }
            }))});

            byte[] encryptedAES = aes.encrypt(aesKey, inputData, iv);
            log.info("Decryption AES - {}", size);
            results.add(new String[]{"AES", "Decryption", String.valueOf(size), String.valueOf(measureTime(() -> {
                try { aes.decrypt(aesKey, encryptedAES, iv); } catch (Exception e) { e.printStackTrace(); }
            }))});

            if(size <= 1000) {
                log.info("Encryption RSA - {}", size);
                results.add(new String[]{"RSA", "Encryption", String.valueOf(size), String.valueOf(measureTime(() -> {
                    try { rsa.encrypt(rsaKeys.getPublic(), inputData); } catch (Exception e) { e.printStackTrace(); }
                }))});

                log.info("Decryption RSA - {}", size);
                byte[] encryptedRSA = rsa.encrypt(rsaKeys.getPublic(), inputData);
                results.add(new String[]{"RSA", "Decryption", String.valueOf(size), String.valueOf(measureTime(() -> {
                    try { rsa.decrypt(rsaKeys.getPrivate(), encryptedRSA); } catch (Exception e) { e.printStackTrace(); }
                }))});
            }

            log.info("Encryption 3DES - {}", size);
            results.add(new String[]{"3DES", "Encryption", String.valueOf(size), String.valueOf(measureTime(() -> {
                try { tripleDES.encrypt(tripleDESKey, inputData, ivTripleDes); } catch (Exception e) { e.printStackTrace(); }
            }))});

            log.info("Decryption 3DES - {}", size);
            byte[] encrypted3DES = tripleDES.encrypt(tripleDESKey, inputData, ivTripleDes);
            results.add(new String[]{"3DES", "Decryption", String.valueOf(size), String.valueOf(measureTime(() -> {
                try { tripleDES.decrypt(tripleDESKey, encrypted3DES, ivTripleDes); } catch (Exception e) { e.printStackTrace(); }
            }))});
        }
    }

    private double measureTime(Runnable function) {
        long startTime = System.nanoTime();
        function.run();
        long endTime = System.nanoTime();
        return (double) (endTime - startTime) / 1_000_000;
    }

    private void saveResultsToCSV(List<String[]> dataLines, String name) {
        try (FileWriter csvWriter = new FileWriter("cipher_comparison_results" + name + ".csv")) {
            for (String[] rowData : dataLines) {
                csvWriter.append(String.join(",", rowData)).append("\n");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
