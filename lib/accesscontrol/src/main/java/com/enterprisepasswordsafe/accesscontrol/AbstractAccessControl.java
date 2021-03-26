package com.enterprisepasswordsafe.accesscontrol;

import com.alsutton.cryptography.AsymmetricKeySupplier;
import com.alsutton.cryptography.Decrypter;
import com.alsutton.cryptography.Encrypter;
import com.enterprisepasswordsafe.cryptography.ObjectWithEncryptableKey;
import com.enterprisepasswordsafe.cryptography.ObjectWithUUID;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

public abstract class AbstractAccessControl
        extends ObjectWithEncryptableKey
        implements ObjectWithUUID {

    private final AsymmetricKeySupplier asymmetricKeySupplier = new AsymmetricKeySupplier();

    public abstract PublicKey getReadKey();

    public abstract void setReadKey(PublicKey readKey);

    public abstract PrivateKey getModifyKey();

    public abstract void setModifyKey(PrivateKey privateKey);

    public abstract byte[] getEncryptedReadKey();

    public abstract void setEncryptedReadKey(byte[] data);

    public abstract byte[] getEncryptedModifyKey();

    public abstract void setEncryptedModifyKey(byte[] data);

    public abstract String getUuid();

    public void encryptKeys(Encrypter encrypter) throws GeneralSecurityException {
        setEncryptedReadKey(encryptKey(this::getReadKey, encrypter));
        setEncryptedModifyKey(encryptKey(this::getModifyKey, encrypter));
    }

    public void decryptKeys(Decrypter decrypter) throws GeneralSecurityException {
        byte[] keyData = decrypt(this::getEncryptedReadKey, decrypter);
        setReadKey(asymmetricKeySupplier.convertToPublicKey(keyData));

        keyData = decrypt(this::getEncryptedModifyKey, decrypter);
        setModifyKey(asymmetricKeySupplier.convertToPrivateKey(keyData));
    }
}
