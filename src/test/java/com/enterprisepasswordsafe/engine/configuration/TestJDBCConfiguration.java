package com.enterprisepasswordsafe.engine.configuration;

import com.enterprisepasswordsafe.engine.Repositories;
import com.enterprisepasswordsafe.engine.dbabstraction.SupportedDatabase;
import com.enterprisepasswordsafe.engine.dbpool.DatabasePool;
import com.enterprisepasswordsafe.engine.dbpool.DatabasePoolFactory;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;

public class TestJDBCConfiguration {

    private static DatabasePool testingPool;

    public static synchronized void forceTestingConfiguration()
            throws SQLException, ClassNotFoundException, GeneralSecurityException, IllegalAccessException, UnsupportedEncodingException, InstantiationException {
        if (testingPool != null) {
            return;
        }

        JDBCConfigurationRepository testConfigRepository = new TestConfigurationJDBCConfigurationRepository();
        Repositories.jdbcConfigurationRepository = testConfigRepository;
        testingPool = new DatabasePool(testConfigRepository.load());
        testingPool.initialiseDatabase();
    }
}
