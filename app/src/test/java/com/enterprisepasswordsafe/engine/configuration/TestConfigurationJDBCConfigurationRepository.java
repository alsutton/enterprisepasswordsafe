package com.enterprisepasswordsafe.engine.configuration;

import com.enterprisepasswordsafe.database.vendorspecific.SupportedDatabase;

import java.util.function.Supplier;

public class TestConfigurationJDBCConfigurationRepository
    implements Supplier<JDBCConnectionInformation> {
    @Override
    public JDBCConnectionInformation get() {
        return new JDBCConnectionInformation() {
            @Override
            public boolean isValid() {
                return true;
            }

            @Override
            public String getDbType() {
                return SupportedDatabase.APACHE_DERBY.getType();
            }

            @Override
            public String getDriver() {
                return "org.apache.derby.jdbc.EmbeddedDriver";
            }

            @Override
            public String getUrl() {
                return "jdbc:derby:memory:myDB;create=true";
            }

            @Override
            public String getUsername() {
                return "";
            }

            @Override
            public String getPassword() {
                return "";
            }
        };
    }
}
