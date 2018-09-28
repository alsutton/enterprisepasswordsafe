package com.enterprisepasswordsafe.engine.configuration;

import com.enterprisepasswordsafe.engine.dbabstraction.SupportedDatabase;

import java.security.GeneralSecurityException;

public class TestConfigurationJDBCConfigurationRepository
    implements JDBCConfigurationRepository {
    @Override
    public JDBCConnectionInformation load() throws GeneralSecurityException {
        JDBCConnectionInformation configuration = new JDBCConnectionInformation();
        configuration.dbType = SupportedDatabase.APACHE_DERBY.getType();
        configuration.driver = "org.apache.derby.jdbc.EmbeddedDriver";
        configuration.url = "jdbc:derby:memory:myDB;create=true";
        configuration.password = "";
        configuration.username = "";
        return configuration;
    }

    @Override
    public void store(JDBCConnectionInformation jdbcConnectionInformation) {
        throw new RuntimeException("Not implemented");
    }
}
