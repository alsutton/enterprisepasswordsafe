package com.enterprisepasswordsafe.engine;

import com.enterprisepasswordsafe.database.dbpool.DatabasePoolFactory;
import com.enterprisepasswordsafe.engine.configuration.EnvironmentVariableBackedJDBCConfigurationRepository;
import com.enterprisepasswordsafe.engine.configuration.JDBCConnectionInformation;

import java.util.function.Supplier;

public class Repositories {
    public static Supplier<JDBCConnectionInformation> jdbcConfigurationRepository
            = new EnvironmentVariableBackedJDBCConfigurationRepository();

    public static DatabasePoolFactory databasePoolFactory
            = new DatabasePoolFactory();
}
