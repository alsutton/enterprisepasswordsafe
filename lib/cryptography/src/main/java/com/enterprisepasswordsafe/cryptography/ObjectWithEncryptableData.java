package com.enterprisepasswordsafe.cryptography;

import com.alsutton.cryptography.Decrypter;
import com.alsutton.cryptography.Encrypter;

import java.security.GeneralSecurityException;
import java.util.function.Supplier;

public class ObjectWithEncryptableData {
    /**
     * Encrypt some data from a supplier and provide it to a consumer.
     *
     * @param data The data to encrypt
     * @param encrypter The {@link Encrypter} to use to encrypt the data.
     *
     * @return The encrypted data.
     */

    public byte[] encrypt(byte[] data, final Encrypter encrypter)
            throws GeneralSecurityException {
        if(data == null) {
            return null;
        }

        return encrypter.apply(data);
    }

    /**
     * Decrypt some data from a supplier and provide it to a consumer.
     *
     * @param dataSupplier Supplier of the encrypted data.
     * @param decrypter The {@link Decrypter} to use to decrypt the data.
     *
     * @return the decrypted data.
     */

    public byte[] decrypt(final Supplier<byte[]> dataSupplier, final Decrypter decrypter)
            throws GeneralSecurityException {
        byte[] data = dataSupplier.get();
        if(data == null) {
            return null;
        }

        return decrypter.apply(data);
    }
}
