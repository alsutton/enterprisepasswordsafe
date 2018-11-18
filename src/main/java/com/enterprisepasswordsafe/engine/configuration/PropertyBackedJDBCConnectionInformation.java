package com.enterprisepasswordsafe.engine.configuration;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.prefs.Preferences;

public class PropertyBackedJDBCConnectionInformation
        extends GenericJDBCConnectionInformation {
    private static final byte[] PASSWORD_AES_KEY = { 84, -54, 102, -106, 30,
            -63, 98, 125, 52, 22, 34, 44, -39, 86, 11, -120 };

    private static final String DB_TYPE_PARAMETER = "eps_db.type";

    private static final String DRIVER_PARAMETER = "eps_jdbc.driver";

    private static final String URL_PARAMETER = "eps_jdbc.url";

    private static final String USERNAME_PARAMETER = "eps_jdbc.username";

    private static final String PASSWORD_PARAMETER = "eps_jdbc.password";

    private static final String ENCRYPTED_PASSWORD_PARAMETER = "eps_jdbc.password.encrypted";

    public PropertyBackedJDBCConnectionInformation() {
        super();
    }

    PropertyBackedJDBCConnectionInformation(Preferences prefs) throws GeneralSecurityException {
        super(
                prefs.get(DB_TYPE_PARAMETER, null),
                prefs.get(DRIVER_PARAMETER, null),
                prefs.get(URL_PARAMETER, null),
                prefs.get(USERNAME_PARAMETER, null),
                decodePassword(prefs)
        );
    }

    private static String decodePassword(Preferences prefs) throws GeneralSecurityException {
        byte[] passwordBytes = prefs.getByteArray(ENCRYPTED_PASSWORD_PARAMETER, null);
        if(passwordBytes == null) {
            return prefs.get(PASSWORD_PARAMETER, null);
        }
        return decryptPasswordText(passwordBytes);
    }

    private static String decryptPasswordText(byte[] data)
            throws GeneralSecurityException {
        byte[] original = feedThroughCipher(Cipher.DECRYPT_MODE, data);
        return new String(original);
    }

    private static byte[] feedThroughCipher(int mode, byte[] data)
            throws GeneralSecurityException {
        SecretKey cryptoKey = new SecretKeySpec(PASSWORD_AES_KEY, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(mode, cryptoKey);
        return cipher.doFinal(data);
    }
}
