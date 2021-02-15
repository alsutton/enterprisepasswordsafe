package com.enterprisepasswordsafe.model.utils;

import com.alsutton.cryptography.TwoLevelEncrypter;
import com.enterprisepasswordsafe.model.persisted.Password;
import com.enterprisepasswordsafe.model.persisted.PasswordAccessControl;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public class PasswordEncrypter {

    public void encrypt(Password password, PasswordAccessControl passwordAccessControl)
            throws InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException,
            NoSuchProviderException, NoSuchAlgorithmException {
        TwoLevelEncrypter encrypter = new TwoLevelEncrypter(passwordAccessControl.getModifyKey());
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        password.getDecryptedProperties().store(os, "");
        password.setData(encrypter.apply(os.toByteArray()));
    }
}
