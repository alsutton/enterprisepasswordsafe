package com.enterprisepasswordsafe.model.utils;

import com.alsutton.cryptography.TwoLevelDecrypter;
import com.enterprisepasswordsafe.model.persisted.Password;
import com.enterprisepasswordsafe.model.persisted.PasswordAccessControl;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.util.Properties;

public class PasswordDecrypter {

    public void decrypt(Password password, PasswordAccessControl passwordAccessControl)
            throws InvalidKeyException, IOException, BadPaddingException, IllegalBlockSizeException {
        TwoLevelDecrypter twoLevelDecrypter = new TwoLevelDecrypter(passwordAccessControl.getReadKey());
        byte[] decryptedProperties = twoLevelDecrypter.apply(password.getData());
        Properties properties = new Properties();
        properties.load(new ByteArrayInputStream(decryptedProperties));
        password.setDecryptedProperties(properties);
    }
}
