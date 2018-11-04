package com.enterprisepasswordsafe.engine.accesscontrol;

import com.enterprisepasswordsafe.engine.utils.Constants;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.UnsupportedEncodingException;
import java.security.*;

public class AccessControl implements Comparable<AccessControl> {

    private static final String FIRST_LEVEL_ENCRYPTION_ALGORITHM = "RSA";
    private static final String SECOND_LEVEL_ENCRYPTION_ALGORITHM = "AES";
    private static final int AES_KEY_SIZE_IN_BITS = 128;
    private static final int JCE_PROVIDER_BITS_PER_BYTE = 8;

    private String itemId;
    private String accessorId;
    private PrivateKey modifyKey;
    private PublicKey readKey;

    protected AccessControl(final String newItemId, final String newAccessorId,
                         final PrivateKey newModifyKey, final PublicKey newReadKey) {
        itemId = newItemId;
        accessorId = newAccessorId;
        modifyKey = newModifyKey;
        readKey = newReadKey;
    }

    public String getItemId() {
        return itemId;
    }

    public String getAccessorId() {
        return accessorId;
    }

    public PrivateKey getModifyKey() {
        return modifyKey;
    }

    public PublicKey getReadKey() {
        return readKey;
    }

    private byte[] generateSecondLevelKey()
            throws NoSuchAlgorithmException {
        KeyGenerator kgen = KeyGenerator.getInstance(SECOND_LEVEL_ENCRYPTION_ALGORITHM);
        kgen.init(AES_KEY_SIZE_IN_BITS);             // 192 and 256 bits may not be available
        SecretKey skey = kgen.generateKey();
        return skey.getEncoded();
    }

    public final byte[] encrypt(final String data)
            throws GeneralSecurityException, UnsupportedEncodingException {
        if( data == null ) {
            return null;
        }
        return encryptToBinary(data);
    }

    public final byte[] encryptToBinary(final String data)
            throws GeneralSecurityException, UnsupportedEncodingException {
        if (modifyKey == null) {
            throw new GeneralSecurityException("Illegal attempt to update an object");
        }

        // Decrypt the data
        Cipher cipher = Cipher.getInstance(FIRST_LEVEL_ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, modifyKey);

        // Convert it into a string
        byte[] secondLevelKey = generateSecondLevelKey();
        byte[] encryptedKey = cipher.doFinal(secondLevelKey);

        // Encrypt the data.
        byte[] encryptedData = secondLevelEncrypt(secondLevelKey, data);

        // Combine the two blocks into one
        byte[] finalData = new byte[encryptedKey.length + encryptedData.length];
        System.arraycopy(encryptedKey, 0, finalData, 0, encryptedKey.length);
        System.arraycopy(encryptedData, 0, finalData, encryptedKey.length, encryptedData.length);

        return finalData;
    }

    private byte[] secondLevelEncrypt(final byte[] accessKey, final String data)
            throws GeneralSecurityException, UnsupportedEncodingException {
        if (data == null) {
            return null;
        }

        SecretKeySpec skeySpec = new SecretKeySpec(accessKey, SECOND_LEVEL_ENCRYPTION_ALGORITHM);
        Cipher cipher = Cipher.getInstance(SECOND_LEVEL_ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        return cipher.doFinal(data.getBytes(Constants.STRING_CODING_FORMAT));
    }

    public final String decrypt(final byte[] data)
            throws GeneralSecurityException, UnsupportedEncodingException {
        if( data == null) {
            return null;
        }

        return decryptFromBinary(data);
    }

    public final String decryptFromBinary(final byte[] data)
            throws GeneralSecurityException, UnsupportedEncodingException {
        byte[] decryptedData = decryptVersionTwoData(data);
        return new String(decryptedData, Constants.STRING_CODING_FORMAT);
    }

    private byte[] decryptVersionTwoData(final byte[] data)
            throws GeneralSecurityException {
        if (readKey == null) {
            throw new GeneralSecurityException("Illegal attempt to read an object");
        }

        // Extract the second level key and decode it.
        byte[] keyData = decryptVersionOneData(data);

        // This is needed because the bouncy castle provider drops leading zeros.
        int encryptionKeySizeByes =  AES_KEY_SIZE_IN_BITS / JCE_PROVIDER_BITS_PER_BYTE;
        int missingBytes = encryptionKeySizeByes - keyData.length;
        if (missingBytes != 0) {
            byte[] oldkeyData = keyData;
            keyData = new byte[encryptionKeySizeByes];
            int i = 0;
            for (; i < missingBytes; i++) {
                keyData[i] = 0;
            }
            System.arraycopy(oldkeyData, 0, keyData, i, oldkeyData.length);
        }

        SecretKeySpec skeySpec = new SecretKeySpec(keyData, SECOND_LEVEL_ENCRYPTION_ALGORITHM);

        Cipher cipher = getVersionTwoCipher();
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        return cipher.doFinal(data, AES_KEY_SIZE_IN_BITS, (data.length - AES_KEY_SIZE_IN_BITS));
    }

    private byte[] decryptVersionOneData(final byte[] data)
            throws GeneralSecurityException {
        if (readKey == null) {
            throw new GeneralSecurityException("Illegal attempt to read an object");
        }

        Cipher cipher = getVersionOneCipher();
        cipher.init(Cipher.DECRYPT_MODE, readKey);
        return cipher.doFinal(data, 0, AccessControl.AES_KEY_SIZE_IN_BITS);
    }

    private static Cipher getVersionTwoCipher() throws NoSuchAlgorithmException, NoSuchPaddingException {
        return Cipher.getInstance(SECOND_LEVEL_ENCRYPTION_ALGORITHM);
    }

    private static Cipher getVersionOneCipher() throws NoSuchAlgorithmException, NoSuchPaddingException {
        return Cipher.getInstance(FIRST_LEVEL_ENCRYPTION_ALGORITHM);
    }

    @Override
    public int compareTo(final AccessControl otherAc) {
        int itemIdComparison = itemId.compareTo(otherAc.itemId);
        if( itemIdComparison != 0 ) {
            return itemIdComparison;
        }

        int comparison = compareKeys(modifyKey, otherAc.modifyKey);
        if (comparison != 0) {
            return comparison;
        }

        return compareKeys(readKey, otherAc.readKey);
    }

    private int compareKeys(Key thisKey, Key otherKey) {
        if( thisKey == null) {
            return otherKey == null ? 0 : Integer.MIN_VALUE;
        }
        return otherKey == null ? Integer.MAX_VALUE : 0;
    }
}
