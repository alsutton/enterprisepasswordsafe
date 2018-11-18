package com.enterprisepasswordsafe.engine.configuration;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.util.prefs.Preferences;

public interface JDBCConnectionInformation {

    public boolean isValid();

    public String getDbType();

    public String getDriver();

    public String getUrl();

    public String getUsername();

    public String getPassword();
}
