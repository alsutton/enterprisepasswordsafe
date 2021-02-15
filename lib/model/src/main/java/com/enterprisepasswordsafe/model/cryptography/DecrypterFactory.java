package com.enterprisepasswordsafe.model.cryptography;

import com.alsutton.cryptography.Decrypter;
import com.alsutton.cryptography.SymmetricDecrypter;
import com.enterprisepasswordsafe.cryptography.ObjectWithSecretKey;
import com.enterprisepasswordsafe.cryptography.ObjectWithUUID;

import java.security.NoSuchAlgorithmException;

public class DecrypterFactory {
    private ObjectWithSecretKey keyHolder;

    public DecrypterFactory(ObjectWithSecretKey keyHolder) {
        this.keyHolder = keyHolder;
    }

    public Decrypter decrypterFor(ObjectWithUUID object)
            throws NoSuchAlgorithmException {
        return new SymmetricDecrypter(keyHolder.getKey(), IVUtils.generateFrom(object.getUuid()));
    }
}
