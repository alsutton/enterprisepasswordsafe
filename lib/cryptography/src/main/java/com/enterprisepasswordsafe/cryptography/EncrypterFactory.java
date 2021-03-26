package com.enterprisepasswordsafe.cryptography;

import com.alsutton.cryptography.Encrypter;
import com.alsutton.cryptography.SymmetricEncrypter;

import java.security.NoSuchAlgorithmException;

public class EncrypterFactory {
    private ObjectWithSecretKey keyHolder;

    public EncrypterFactory(ObjectWithSecretKey keyHolder) {
        this.keyHolder = keyHolder;
    }

    public Encrypter encrypterFor(ObjectWithUUID object)
            throws NoSuchAlgorithmException {
        return new SymmetricEncrypter(keyHolder.getKey(), IVUtils.generateFrom(object.getUuid()));
    }
}
