package com.enterprisepasswordsafe.engine;

import com.enterprisepasswordsafe.database.dbpool.DatabasePoolFactory;
import com.enterprisepasswordsafe.engine.configuration.EnvironmentVariableBackedJDBCConfigurationRepository;
import com.enterprisepasswordsafe.engine.configuration.JDBCConfigurationRepository;

public class Repositories {
    public static JDBCConfigurationRepository jdbcConfigurationRepository
            = new EnvironmentVariableBackedJDBCConfigurationRepository();

    public static DatabasePoolFactory databasePoolFactory
            = new DatabasePoolFactory();
}
