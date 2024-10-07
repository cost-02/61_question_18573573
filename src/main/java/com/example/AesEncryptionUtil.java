package com.example;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.util.Base64;

public class AesEncryptionUtil {

    public static void main(String[] args) throws Exception {
        String data = "Dati da criptare";
        
        // Genera la chiave AES a 256 bit
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256); // Usa 256 per AES-256.
        SecretKey secretKey = keyGenerator.generateKey();

        // Converti la chiave in una forma utilizzabile
        byte[] key = secretKey.getEncoded();
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, "AES");

        // Criptazione
        String encryptedData = encrypt(data, secretKeySpec);
        System.out.println("Dati criptati: " + encryptedData);

        // Decriptazione
        String decryptedData = decrypt(encryptedData, secretKeySpec);
        System.out.println("Dati decriptati: " + decryptedData);
    }

    public static String encrypt(String data, SecretKeySpec key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(data.getBytes());
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encryptedData, SecretKeySpec key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] original = cipher.doFinal(Base64.getDecoder().decode(encryptedData));
        return new String(original);
    }
}
