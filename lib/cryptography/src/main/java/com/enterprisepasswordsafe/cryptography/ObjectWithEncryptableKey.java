package com.enterprisepasswordsafe.cryptography;

import com.alsutton.cryptography.Encrypter;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.util.function.Supplier;

public class ObjectWithEncryptableKey extends ObjectWithEncryptableData {

    /**
     * Encrypt a key from a supplier.
     *
     * @param keySupplier Supplier of the key material.
     * @param keyEncrypter The Encrypter to use to encrypt the key.
     *
     * @return The encrypt key material.
     */

    public byte[] encryptKey(final Supplier<Key> keySupplier, final Encrypter keyEncrypter)
            throws GeneralSecurityException {
        Key key = keySupplier.get();
        if (key == null) {
            return null;
        }
        return encrypt(key.getEncoded(), keyEncrypter);
    }
}
