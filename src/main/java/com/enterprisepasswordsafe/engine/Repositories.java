package com.enterprisepasswordsafe.engine;

import com.enterprisepasswordsafe.engine.configuration.JDBCConfigurationRepository;
import com.enterprisepasswordsafe.engine.configuration.PropertyBackedJDBCConfigurationRepository;
import com.enterprisepasswordsafe.engine.dbpool.DatabasePoolFactory;

public class Repositories {
    public static JDBCConfigurationRepository jdbcConfigurationRepository
            = new PropertyBackedJDBCConfigurationRepository();

    public static DatabasePoolFactory databasePoolFactory
            = new DatabasePoolFactory();
}
