package com.enterprisepasswordsafe.engine;

import com.enterprisepasswordsafe.engine.configuration.JDBCConfigurationRepository;
import com.enterprisepasswordsafe.engine.configuration.PropertyBackedJDBCConfigurationRepository;

public class Repositories {
    public static JDBCConfigurationRepository jdbcConfigurationRepository
            = new PropertyBackedJDBCConfigurationRepository();
}
