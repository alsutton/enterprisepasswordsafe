package com.enterprisepasswordsafe.engine.configuration;

import com.enterprisepasswordsafe.database.dbpool.DatabasePool;
import com.enterprisepasswordsafe.engine.Repositories;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;

public class TestJDBCConfiguration {

    private static DatabasePool testingPool;

    public static synchronized void forceTestingConfiguration()
            throws SQLException, ClassNotFoundException, GeneralSecurityException, IllegalAccessException, UnsupportedEncodingException, InstantiationException, NoSuchMethodException, InvocationTargetException {
        if (testingPool != null) {
            return;
        }

        JDBCConfigurationRepository testConfigRepository = new TestConfigurationJDBCConfigurationRepository();
        Repositories.jdbcConfigurationRepository = testConfigRepository;
        testingPool = new DatabasePool(testConfigRepository.load());
        testingPool.initialiseDatabase();
    }
}
