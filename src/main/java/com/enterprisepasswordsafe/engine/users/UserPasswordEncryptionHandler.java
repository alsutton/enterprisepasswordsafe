package com.enterprisepasswordsafe.engine.users;

import com.enterprisepasswordsafe.engine.database.Encrypter;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.security.GeneralSecurityException;

public class UserPasswordEncryptionHandler implements Encrypter {

    private static final byte[] PBE_SALT = {(byte) 0xc7, (byte) 0x73,
            (byte) 0x21, (byte) 0x8c, (byte) 0x7e, (byte) 0xc8, (byte) 0xee,
            (byte) 0x99 };

    private static final int PBE_ITERATIONS = 3;

    private static final String PBE_ALGORITHM = "PBEWithMD5AndDES";

    private final SecretKey encryptionKey;

    public UserPasswordEncryptionHandler(final String password)
            throws GeneralSecurityException {
        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
        SecretKeyFactory keyFac = SecretKeyFactory.getInstance(PBE_ALGORITHM);
        encryptionKey = keyFac.generateSecret(pbeKeySpec);
    }

    @Override
    public byte[] encrypt(byte[] data)
            throws GeneralSecurityException {
        PBEParameterSpec pbeParamSpec = new PBEParameterSpec(PBE_SALT, PBE_ITERATIONS);
        Cipher pbeCipher = Cipher.getInstance(PBE_ALGORITHM);
        pbeCipher.init(Cipher.ENCRYPT_MODE, encryptionKey, pbeParamSpec);
        return pbeCipher.doFinal(data);
    }

    public byte[] decrypt(byte[] data)
            throws GeneralSecurityException {
        PBEParameterSpec pbeParamSpec = new PBEParameterSpec(PBE_SALT, PBE_ITERATIONS);
        Cipher pbeCipher = Cipher.getInstance(PBE_ALGORITHM);
        pbeCipher.init(Cipher.DECRYPT_MODE, encryptionKey, pbeParamSpec);
        return pbeCipher.doFinal(data);
    }
}

