package com.enterprisepasswordsafe.configuration;

public class GenericJDBCConnectionInformation
        implements JDBCConnectionInformation {

    public String dbType;

    public String driver;

    public String url;

    public String username;

    public String password;

    public GenericJDBCConnectionInformation() {
        super();
    }

    GenericJDBCConnectionInformation(final String dbType, final String driver,
            final String url, final String username, final String password) {
        this.dbType = dbType;
        this.driver = driver;
        this.url = url;
        this.username = username;
        this.password = password;
    }


    public boolean isValid() {
        return dbType != null && driver != null && url != null && username != null && password != null;
    }

    @Override
    public int hashCode() {
        return dbType.hashCode() | driver.hashCode() | url.hashCode()
                | username.hashCode() | password.hashCode();
    }

    public boolean equals(GenericJDBCConnectionInformation otherConfig) {
        return otherConfig != null && (dbType.equals(otherConfig.dbType)
            && driver.equals(otherConfig.driver) && url.equals(otherConfig.url)
            && username.equals(otherConfig.username) && password.equals(otherConfig.password));
    }

    @Override
    public String toString() {
        return  "DB Type: " + dbType + ", Driver: " + driver + ", URL: " + url +
                ", Username: " + username + ", Password: " + password;
    }

    public String getDbType() {
        return dbType;
    }

    public String getDriver() {
        return driver;
    }

    public String getUrl() {
        return url;
    }

    public String getUsername() {
        return username;
    }

    public String getPassword() {
        return password;
    }
}
