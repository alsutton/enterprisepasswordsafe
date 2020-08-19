package com.enterprisepasswordsafe.engine.configuration;

import com.enterprisepasswordsafe.database.dbpool.DatabasePool;
import com.enterprisepasswordsafe.engine.Repositories;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.function.Supplier;

public class TestJDBCConfiguration {

    private static DatabasePool testingPool;

    public static synchronized void forceTestingConfiguration()
            throws SQLException, ClassNotFoundException, GeneralSecurityException, IllegalAccessException, UnsupportedEncodingException, InstantiationException, NoSuchMethodException, InvocationTargetException {
        if (testingPool != null) {
            return;
        }

        Supplier<JDBCConnectionInformation> testConfigRepository = new TestConfigurationJDBCConfigurationRepository();
        Repositories.jdbcConfigurationRepository = testConfigRepository;
        testingPool = new DatabasePool(testConfigRepository.get());
        testingPool.initialiseDatabase();
    }
}
