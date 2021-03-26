package com.enterprisepasswordsafe.cryptography;

import com.alsutton.cryptography.SymmetricKeySupplier;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class IVUtils {

    private static int IV_SIZE = new SymmetricKeySupplier().getIVSizeInBytes();

    /**
     * Convert and Long to an IV.
     */

    public static byte[] generateFrom(String value)
            throws NoSuchAlgorithmException {
        byte[] iv = new byte[IV_SIZE];
        int position = 0;
        byte[] seedData = value.getBytes(StandardCharsets.UTF_8);
        MessageDigest digester = MessageDigest.getInstance("SHA-256");
        while(position < iv.length) {
            seedData = digester.digest(seedData);
            int amountToCopy = Math.min(seedData.length, iv.length - position);
            System.arraycopy(seedData, 0, iv, position, amountToCopy);
            position += amountToCopy;
        }
        return iv;
    }
}
