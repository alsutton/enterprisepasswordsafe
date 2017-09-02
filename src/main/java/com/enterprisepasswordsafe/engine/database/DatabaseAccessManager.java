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

package com.enterprisepasswordsafe.engine.database;

import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.enterprisepasswordsafe.engine.configuration.JDBCConfiguration;
import com.enterprisepasswordsafe.engine.database.exceptions.DatabaseUnavailableException;
import com.enterprisepasswordsafe.engine.dbabstraction.DALFactory;
import com.enterprisepasswordsafe.engine.dbabstraction.DALInterface;
import com.enterprisepasswordsafe.engine.utils.DatabaseConnectionUtils;


/**
 * Class managing all the business object which may be needed to service the EPS.
 */
public class DatabaseAccessManager {

	/**
	 * The type of database we're dealing with.
	 */

	private final String dbType;

	/**
	 * The connection to the database.
	 */

	private Connection connection;

	/**
	 * The database abstraction layer in use
	 */

	private DALInterface databaseAbstractionLayer;

	/**
	 * A temporary cache for objects which last the lifetime of this BOM.
	 */

	private Map<String,Object> cache;

	public DatabaseAccessManager() throws SQLException, GeneralSecurityException {
		dbType = JDBCConfiguration.getConfiguration().getDBType();
	}

	/**
	 * Close this BOM, closing all the closable DAOs.
	 */

	public void close() {
		if(connection == null) {
			return;
		}

		try {
			if (!connection.isClosed()) {
				commitAndCloseConnection();
			}
		} catch(SQLException e) {
			Logger.getAnonymousLogger().log(Level.WARNING, "Problem closing connection", e);
		}

		connection = null;
	}

	private void commitAndCloseConnection() {
		try {
			try {
				if(!connection.getAutoCommit()) {
					connection.commit();
				}
			} finally {
				DatabaseConnectionUtils.close(connection);
			}
		} catch(Exception ex) {
			Logger.getAnonymousLogger().log(Level.WARNING, "Error commiting data on BOM close", ex);
		}
	}

	public boolean hasOpenConnection() {
		try {
			return connection != null && !connection.isClosed();
		} catch(SQLException sqle) {
			return false;
		}
	}

	/**
	 * Get the connection object used
	 * @throws SQLException
	 */

	public Connection getConnection() throws SQLException {
		if(connection == null || connection.isClosed()) {
			try {
				connection = DriverManager.getConnection("jdbc:apache:commons:dbcp:pwsafe");
			} catch(SQLException e) {
				Logger.getAnonymousLogger().log(Level.WARNING, "Error attempting to get database connection", e);
				throw new DatabaseUnavailableException(e);
			}
		}
		return connection;
	}


	/**
	 * Gets a Database Abstraction Layer object for direct database manipulation.
	 *
	 * @throws ClassNotFoundException
	 * @throws IllegalAccessException
	 * @throws InstantiationException
	 */

	public synchronized DALInterface getDatabaseAbstractionLayer()
		throws InstantiationException, IllegalAccessException, ClassNotFoundException {
		if(databaseAbstractionLayer != null )
			return databaseAbstractionLayer;

        databaseAbstractionLayer = DALFactory.getDAL(dbType);
        databaseAbstractionLayer.setConnection(connection);
        return databaseAbstractionLayer;
	}

	/**
	 * Put a value in the bom cache.
	 *
	 * @param name The name for the value.
	 * @param value The value itself.
	 */

	public synchronized Object cacheValue(String name, Object value){
		if( cache == null ) {
			cache = new HashMap<>();
		}

		return cache.put(name, value);
	}

	public synchronized Object getFromCache(String name){
		if(cache == null)
			return null;

		return cache.get(name);
	}
}
