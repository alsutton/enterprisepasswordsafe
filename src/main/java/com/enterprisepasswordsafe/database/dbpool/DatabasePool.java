/*
 * Copyright (c) 2017 Carbon Security Ltd. <opensource@carbonsecurity.co.uk>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package com.enterprisepasswordsafe.database.dbpool;

import com.enterprisepasswordsafe.database.schema.SchemaVersion;
import com.enterprisepasswordsafe.database.vendorspecific.DALFactory;
import com.enterprisepasswordsafe.database.vendorspecific.DALInterface;
import com.enterprisepasswordsafe.engine.configuration.JDBCConnectionInformation;
import org.apache.commons.dbcp2.*;
import org.apache.commons.pool2.ObjectPool;
import org.apache.commons.pool2.impl.GenericObjectPool;

import java.io.UnsupportedEncodingException;
import java.lang.reflect.InvocationTargetException;
import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

public final class DatabasePool implements AutoCloseable {

    private static final Object VERIFICATION_LOCK = new Object();

    private final JDBCConnectionInformation connectionInformation;

    public DatabasePool(final JDBCConnectionInformation connectionInformation) throws ClassNotFoundException, SQLException {
        this.connectionInformation = connectionInformation;
        Class.forName(connectionInformation.getDriver());

        ConnectionFactory connectionFactory =
                new DriverManagerConnectionFactory(connectionInformation.getUrl(),
                        connectionInformation.getUsername(), connectionInformation.getPassword());
        PoolableConnectionFactory poolableConnectionFactory = new PoolableConnectionFactory(connectionFactory, null);
        ObjectPool<PoolableConnection> connectionPool = new GenericObjectPool<>(poolableConnectionFactory);
        poolableConnectionFactory.setPool(connectionPool);

        Class.forName("org.apache.commons.dbcp2.PoolingDriver");
        PoolingDriver driver = (PoolingDriver) DriverManager.getDriver("jdbc:apache:commons:dbcp:");
        driver.registerPool("pwsafe", connectionPool);
    }

    @Override
    public void close() {
    	try {
	        PoolingDriver driver = (PoolingDriver) DriverManager.getDriver("jdbc:apache:commons:dbcp:");
	        driver.closePool("pwsafe");
    	} catch(SQLException sqle) {
    		Logger.getAnonymousLogger().log(Level.WARNING, "Error shutting database pool", sqle);
    	}
    }

    @Override
	public int hashCode() {
        if (connectionInformation != null) {
            return connectionInformation.hashCode();
        }

        return super.hashCode();
    }

    @Override
	public boolean equals(final Object otherObject) {
        if (!(otherObject instanceof DatabasePool)) {
            return false;
        }

        DatabasePool otherPool = (DatabasePool) otherObject;
        return connectionInformation.equals(otherPool.connectionInformation);
    }

    public Connection getConnection() throws SQLException {
        return DriverManager.getConnection("jdbc:apache:commons:dbcp:pwsafe");
    }

    public boolean isUsingConfiguration(JDBCConnectionInformation configuration) {
        return connectionInformation != null && connectionInformation.equals(configuration);
    }

    public boolean isConfigured() {
        try {
            PoolingDriver driver = (PoolingDriver) DriverManager.getDriver("jdbc:apache:commons:dbcp:");
            return driver.getConnectionPool("pwsafe") != null;
        } catch(SQLException sqle) {
            return false;
        }
    }

    public void initialiseDatabase() throws SQLException,
            InstantiationException, IllegalAccessException, UnsupportedEncodingException, GeneralSecurityException, NoSuchMethodException, InvocationTargetException {
        DALInterface databaseAbstractionLayer = DALFactory.getDAL(connectionInformation.getDbType());

        try (Connection conn = getConnection()) {
            databaseAbstractionLayer.setConnection(conn);
            new SchemaVersion().update();
        } catch (SQLException | GeneralSecurityException | UnsupportedEncodingException e) {
            Logger.getAnonymousLogger().log(Level.SEVERE, "Problem during database creation.", e);
            throw e;
        }
    }



    public boolean isValid() {
        synchronized (VERIFICATION_LOCK) {
            return hasValidParameters() && isConfigurationUsable();
        }
    }

    private boolean isConfigurationUsable() {
        try (DatabasePool pool = new DatabasePool(connectionInformation)) {
            return isPoolUsable(pool);
        } catch (SQLException | ClassNotFoundException e) {
            return false;
        }
    }

    private boolean isPoolUsable(final DatabasePool pool) {
        try(Connection connection = pool.getConnection()) {
            return isConnectionUsable(connection);
        } catch (SQLException e) {
            return false;
        }
    }

    private boolean isConnectionUsable(final Connection connection) {
        try {
            DatabaseMetaData metaData = connection.getMetaData();
            Logger.getAnonymousLogger().log(Level.INFO, "Connecting to " + metaData.getDatabaseProductName());
            return true;
        } catch (SQLException e) {
            return false;
        }
    }

    private boolean hasValidParameters() {
        if (!connectionInformation.isValid()) {
            return false;
        }

        try {
            Class.forName(connectionInformation.getDriver());
        } catch (ClassNotFoundException e) {
            Logger.getAnonymousLogger().log(Level.SEVERE, "Error testing database.", e);
            return false;
        }

        return true;
    }

}
