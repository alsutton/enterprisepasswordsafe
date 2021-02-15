package com.enterprisepasswordsafe.model.cryptography;

import com.alsutton.cryptography.Encrypter;
import com.alsutton.cryptography.SymmetricEncrypter;
import com.enterprisepasswordsafe.cryptography.ObjectWithSecretKey;
import com.enterprisepasswordsafe.cryptography.ObjectWithUUID;

import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.util.function.Supplier;

public class EncrypterFactory {
    private Supplier<SecretKey> keyHolder;

    public EncrypterFactory(ObjectWithSecretKey keyHolder) {
        this.keyHolder = keyHolder::getKey;
    }

    public EncrypterFactory(SecretKey secretKey) {
        this.keyHolder = () -> secretKey;
    }

    public Encrypter encrypterFor(ObjectWithUUID object)
            throws NoSuchAlgorithmException {
        return new SymmetricEncrypter(keyHolder.get(), IVUtils.generateFrom(object.getUuid()));
    }
}
