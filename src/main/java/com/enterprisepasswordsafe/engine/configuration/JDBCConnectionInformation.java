package com.enterprisepasswordsafe.engine.configuration;

public interface JDBCConnectionInformation {

    boolean isValid();

    String getDbType();

    String getDriver();

    String getUrl();

    String getUsername();

    String getPassword();
}
