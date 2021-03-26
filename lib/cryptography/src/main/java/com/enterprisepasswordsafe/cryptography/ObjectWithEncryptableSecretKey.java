package com.enterprisepasswordsafe.cryptography;

import com.alsutton.cryptography.Decrypter;
import com.alsutton.cryptography.Encrypter;
import com.alsutton.cryptography.SymmetricKeySupplier;

import javax.crypto.SecretKey;
import java.security.GeneralSecurityException;
import java.util.function.Supplier;

public abstract class ObjectWithEncryptableSecretKey
        extends ObjectWithEncryptableKey
        implements ObjectWithSecretKey {

    private final SymmetricKeySupplier symmetricKeySupplier = new SymmetricKeySupplier();

    public abstract SecretKey getKey();

    /**
     * Encrypt the {@link SecretKey}
     *
     * @param keyEncrypter The encrypter for the key material.
     *
     * @return The encrypted representation of the key.
     */

    public byte[] encryptKey(final Encrypter keyEncrypter)
            throws GeneralSecurityException {
        return keyEncrypter.apply(getKey().getEncoded());
    }

    /**
     * Decrypt the {@link SecretKey}
     *
     * @param keyDataSupplier Supplier of the encrypted key material.
     * @param keyDecrypter The decrypter for the key material
     *
     * @return The decrypted {@link SecretKey}
     */

    public SecretKey decryptKey(final Supplier<byte[]> keyDataSupplier, final Decrypter keyDecrypter)
            throws GeneralSecurityException {
        byte[] keyData = keyDataSupplier.get();
        if (keyData == null) {
            return null;
        }

        keyData = keyDecrypter.apply(keyData);

        return symmetricKeySupplier.convertToKey(keyData);
    }
}
