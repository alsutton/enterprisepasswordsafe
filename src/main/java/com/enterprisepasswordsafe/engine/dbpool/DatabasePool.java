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

package com.enterprisepasswordsafe.engine.dbpool;

import com.enterprisepasswordsafe.engine.configuration.JDBCConfiguration;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.enterprisepasswordsafe.engine.database.schema.SchemaVersion;
import com.enterprisepasswordsafe.engine.dbabstraction.DALFactory;
import com.enterprisepasswordsafe.engine.dbabstraction.DALInterface;
import com.enterprisepasswordsafe.proguard.ExternalInterface;
import org.apache.commons.dbcp2.*;
import org.apache.commons.pool2.ObjectPool;
import org.apache.commons.pool2.impl.GenericObjectPool;

public final class DatabasePool implements ExternalInterface, AutoCloseable {

    private JDBCConfiguration mJdbcConfiguration = null;

    public DatabasePool(final JDBCConfiguration conf) throws ClassNotFoundException, SQLException {
        Class.forName(conf.getDriver());

        ConnectionFactory connectionFactory =
                new DriverManagerConnectionFactory(conf.getURL(), conf.getUsername(), conf.getPassword());
        PoolableConnectionFactory poolableConnectionFactory =
                new PoolableConnectionFactory(connectionFactory, null);
        ObjectPool<PoolableConnection> connectionPool =
                new GenericObjectPool<>(poolableConnectionFactory);
        poolableConnectionFactory.setPool(connectionPool);

        Class.forName("org.apache.commons.dbcp2.PoolingDriver");
        PoolingDriver driver = (PoolingDriver) DriverManager.getDriver("jdbc:apache:commons:dbcp:");
        driver.registerPool("pwsafe", connectionPool);

        mJdbcConfiguration = conf;
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
        if (mJdbcConfiguration != null) {
            return mJdbcConfiguration.hashCode();
        }

        return super.hashCode();
    }

    @Override
	public boolean equals(final Object otherObject) {
        if (!(otherObject instanceof DatabasePool)) {
            return false;
        }

        DatabasePool otherPool = (DatabasePool) otherObject;
        return mJdbcConfiguration.equals(otherPool.mJdbcConfiguration);
    }

    public Connection getConnection() throws SQLException {
        return DriverManager.getConnection("jdbc:apache:commons:dbcp:pwsafe");
    }

    public boolean isUsingConfiguration(JDBCConfiguration configuration) {
        return mJdbcConfiguration != null && mJdbcConfiguration.equals(configuration);
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
            InstantiationException, IllegalAccessException,
            ClassNotFoundException, UnsupportedEncodingException,
            GeneralSecurityException {

        DALInterface databaseAbstractionLayer = DALFactory.getDAL(mJdbcConfiguration.getDBType());

        try (Connection conn = getConnection()) {
            databaseAbstractionLayer.setConnection(conn);
            new SchemaVersion().create();
        } catch (SQLException | GeneralSecurityException | UnsupportedEncodingException e) {
            Logger.getAnonymousLogger().log(Level.SEVERE, "Problem during database creation.", e);
            throw e;
        }
    }

}
