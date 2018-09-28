package com.enterprisepasswordsafe.engine.configuration;

import java.security.GeneralSecurityException;
import java.util.prefs.BackingStoreException;

public interface JDBCConfigurationRepository {

    JDBCConnectionInformation load() throws GeneralSecurityException;

    void store(JDBCConnectionInformation jdbcConnectionInformation) throws BackingStoreException;
}
