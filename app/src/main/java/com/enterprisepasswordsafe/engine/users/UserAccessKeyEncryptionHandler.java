package com.enterprisepasswordsafe.engine.users;

import com.enterprisepasswordsafe.database.Decrypter;
import com.enterprisepasswordsafe.database.Encrypter;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;

public class UserAccessKeyEncryptionHandler implements Encrypter, Decrypter {

    private static final String ACCESS_KEY_ENCRYPTION_ALGORITHM = "AES";

    /**
     * The password to encrypt with.
     */

    private final SecretKey key;

    /**
     * Constructor. Stores password
     */

    public UserAccessKeyEncryptionHandler(final SecretKey newKey) {
        key = newKey;
    }

    @Override
    public byte[] encrypt(byte[] data)
            throws GeneralSecurityException {
        Cipher pbeCipher = Cipher.getInstance(ACCESS_KEY_ENCRYPTION_ALGORITHM);
        pbeCipher.init(Cipher.ENCRYPT_MODE, key);
        return pbeCipher.doFinal(data);
    }

    /**
     * Method to perform the encryption.
     *
     * @param data The data to encrypt.
     *
     * @return The encrypted representation of the data.
     */

    @Override
    public byte[] decrypt(byte[] data)
            throws GeneralSecurityException {
        Cipher pbeCipher = Cipher.getInstance(ACCESS_KEY_ENCRYPTION_ALGORITHM);
        pbeCipher.init(Cipher.DECRYPT_MODE, key);
        return pbeCipher.doFinal(data);
    }
}
