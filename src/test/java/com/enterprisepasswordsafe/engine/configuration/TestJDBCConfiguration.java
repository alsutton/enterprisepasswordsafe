package com.enterprisepasswordsafe.engine.configuration;

import com.enterprisepasswordsafe.engine.dbabstraction.SupportedDatabase;
import com.enterprisepasswordsafe.engine.dbpool.DatabasePool;
import com.enterprisepasswordsafe.engine.dbpool.DatabasePoolFactory;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;

public class TestJDBCConfiguration {

    private static boolean initialised = false;

    public static synchronized void forceTestingConfiguration()
            throws SQLException, ClassNotFoundException, UnsupportedEncodingException,
                    GeneralSecurityException, InstantiationException, IllegalAccessException {
        if (initialised) {
            return;
        }

        JDBCConfiguration configuration = new JDBCConfiguration();
        configuration.setDatabaseType(SupportedDatabase.APACHE_DERBY.getType());
        configuration.setDriver("org.apache.derby.jdbc.EmbeddedDriver");
        configuration.setURL("jdbc:derby:memory:myDB;create=true");
        configuration.setPassword("");
        configuration.setUsername("");

        JDBCConfiguration.force(configuration);

        DatabasePoolFactory.setConfiguration(JDBCConfiguration.getConfiguration());
        DatabasePool pool = DatabasePoolFactory.getInstance();
        pool.initialiseDatabase();
        initialised = true;
    }
}
