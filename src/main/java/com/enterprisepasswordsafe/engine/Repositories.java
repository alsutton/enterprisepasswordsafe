package com.enterprisepasswordsafe.engine;

import com.enterprisepasswordsafe.engine.configuration.EnvironmentVariableBackedJDBCConfigurationRepository;
import com.enterprisepasswordsafe.engine.configuration.JDBCConfigurationRepository;
import com.enterprisepasswordsafe.engine.dbpool.DatabasePoolFactory;

public class Repositories {
    private static final JDBCConfigurationRepository DEFAULT_JDBC_CONFIGURATION_REPOSITORY
            = new EnvironmentVariableBackedJDBCConfigurationRepository();
    public static JDBCConfigurationRepository jdbcConfigurationRepository
            = DEFAULT_JDBC_CONFIGURATION_REPOSITORY;

    private static final DatabasePoolFactory DEFAULT_DATABASE_POOL_FACTORY
            = new DatabasePoolFactory();
    public static DatabasePoolFactory databasePoolFactory
            = DEFAULT_DATABASE_POOL_FACTORY;

    public static void reset() {
        jdbcConfigurationRepository = DEFAULT_JDBC_CONFIGURATION_REPOSITORY;
        databasePoolFactory = DEFAULT_DATABASE_POOL_FACTORY;
    }
}
