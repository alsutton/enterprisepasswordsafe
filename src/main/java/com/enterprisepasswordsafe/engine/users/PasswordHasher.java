package com.enterprisepasswordsafe.engine.users;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;

public class PasswordHasher {
    private static final String PASSWORD_HASH_ALGORITHM = "MD5";

    public byte[] createHashWithRandomSalt(final String password)
            throws NoSuchAlgorithmException {
        byte[] salt = new byte[4];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(salt);

        byte[] hash = createHash(salt, password);

        byte[] saltedHash = new byte[2 + salt.length + hash.length];
        saltedHash[0] = 2;
        saltedHash[1] = (byte) salt.length;
        System.arraycopy(salt, 0, saltedHash, 2, salt.length);
        System.arraycopy(hash, 0, saltedHash, 2+salt.length, hash.length);

        return saltedHash;
    }

    public boolean equalsSaltedHash(String password, byte[] saltedHash)
            throws NoSuchAlgorithmException {
        byte[] salt;
        byte[] hash;
        switch (saltedHash[0]) {
            case 1:
                salt = null;
                hash = new byte[saltedHash.length-1];
                System.arraycopy(saltedHash, 1, hash, 0, hash.length);
                break;
            case 2:
                int saltLength = (int)saltedHash[1];
                salt = new byte[saltLength];
                System.arraycopy(saltedHash,2,salt,0,saltLength);
                hash = new byte[saltedHash.length - (saltLength+2)];
                System.arraycopy(saltedHash,2+saltLength,hash,0,hash.length);
                break;
            default:
                throw new RuntimeException("Unknown password encoding");
        }

        byte[] calculatedHash = createHash(salt, password);

        return Arrays.equals(calculatedHash, hash);
    }

    private byte[] createHash(final byte[] salt, final String userPassword)
            throws NoSuchAlgorithmException {
        MessageDigest digester = MessageDigest.getInstance(PASSWORD_HASH_ALGORITHM);

        byte[] passwordBytes = userPassword.getBytes();
        if(salt != null) {
            byte[] saltedBytes = new byte[salt.length + passwordBytes.length];
            System.arraycopy(passwordBytes, 0, saltedBytes, 0, passwordBytes.length);
            System.arraycopy(salt, 0, saltedBytes, passwordBytes.length, salt.length);
            passwordBytes = saltedBytes;
        }

        digester.update(passwordBytes);
        return digester.digest();
    }
}
