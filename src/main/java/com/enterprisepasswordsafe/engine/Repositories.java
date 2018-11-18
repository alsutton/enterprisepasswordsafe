package com.enterprisepasswordsafe.engine;

import com.enterprisepasswordsafe.engine.configuration.EnvironmentVariableBackedJDBCConfigurationRepository;
import com.enterprisepasswordsafe.engine.configuration.JDBCConfigurationRepository;
import com.enterprisepasswordsafe.engine.dbpool.DatabasePoolFactory;

public class Repositories {
    public static JDBCConfigurationRepository jdbcConfigurationRepository
            = new EnvironmentVariableBackedJDBCConfigurationRepository();

    public static DatabasePoolFactory databasePoolFactory
            = new DatabasePoolFactory();
}
