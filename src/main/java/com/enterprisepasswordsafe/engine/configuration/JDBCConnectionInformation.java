package com.enterprisepasswordsafe.engine.configuration;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.prefs.Preferences;

public class JDBCConnectionInformation {
    private static final byte[] PASSWORD_AES_KEY = { 84, -54, 102, -106, 30,
            -63, 98, 125, 52, 22, 34, 44, -39, 86, 11, -120 };

    private static final String DB_TYPE_PARAMETER = "eps_db.type";

    private static final String DRIVER_PARAMETER = "eps_jdbc.driver";

    private static final String URL_PARAMETER = "eps_jdbc.url";

    private static final String USERNAME_PARAMETER = "eps_jdbc.username";

    private static final String PASSWORD_PARAMETER = "eps_jdbc.password";

    private static final String ENCRYPTED_PASSWORD_PARAMETER = "eps_jdbc.password.encrypted";

    public String dbType;

    public String driver;

    public String url;

    public String username;

    public String password;

    public JDBCConnectionInformation() {
        super();
    }

    JDBCConnectionInformation(Preferences prefs) throws GeneralSecurityException {
        dbType = prefs.get(DB_TYPE_PARAMETER, null);
        driver = prefs.get(DRIVER_PARAMETER, null);
        url = prefs.get(URL_PARAMETER, null);
        username = prefs.get(USERNAME_PARAMETER, null);
        byte[] passwordBytes = prefs.getByteArray(ENCRYPTED_PASSWORD_PARAMETER, null);
        if (passwordBytes == null) {
            password = prefs.get(PASSWORD_PARAMETER, null);
            if (password != null) {
                prefs.putByteArray(ENCRYPTED_PASSWORD_PARAMETER, encryptPasswordText(password));
                prefs.remove(PASSWORD_PARAMETER);
            }
        } else {
            password = decryptPasswordText(passwordBytes);
        }
    }

    void storeIn(Preferences prefs)
            throws GeneralSecurityException {
        prefs.put(DB_TYPE_PARAMETER, dbType);
        prefs.put(DRIVER_PARAMETER, driver);
        prefs.put(URL_PARAMETER, url);
        prefs.put(USERNAME_PARAMETER, username);
        prefs.putByteArray(ENCRYPTED_PASSWORD_PARAMETER, encryptPasswordText(password));
    }

    public boolean isValid() {
        return dbType != null && driver != null && url != null && username != null && password != null;
    }

    @Override
    public int hashCode() {
        return dbType.hashCode() | driver.hashCode() | url.hashCode()
                | username.hashCode() | password.hashCode();
    }

    public boolean equals(JDBCConnectionInformation otherConfig) {
        return otherConfig != null && (dbType.equals(otherConfig.dbType)
            && driver.equals(otherConfig.driver) && url.equals(otherConfig.url)
            && username.equals(otherConfig.username) && password.equals(otherConfig.password));
    }

    @Override
    public String toString() {
        return  "DB Type: " + dbType + ", Driver: " + driver + ", URL: " + url +
                ", Username: " + username + ", Password: " + password;
    }

    private byte[] encryptPasswordText(String text)
            throws GeneralSecurityException {
        return feedThroughCipher(Cipher.ENCRYPT_MODE, text.getBytes());
    }

    private String decryptPasswordText(byte[] data)
            throws GeneralSecurityException {
        byte[] original = feedThroughCipher(Cipher.DECRYPT_MODE, data);
        return new String(original);
    }

    private byte[] feedThroughCipher(int mode, byte[] data)
            throws GeneralSecurityException {
        SecretKey cryptoKey = new SecretKeySpec(PASSWORD_AES_KEY, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(mode, cryptoKey);
        return cipher.doFinal(data);
    }
}
