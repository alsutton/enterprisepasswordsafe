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

import com.enterprisepasswordsafe.engine.configuration.JDBCConnectionInformation;
import com.enterprisepasswordsafe.engine.database.exceptions.DatabaseUnavailableException;
import com.enterprisepasswordsafe.engine.dbabstraction.DALFactory;
import com.enterprisepasswordsafe.engine.dbabstraction.DALInterface;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;


/**
 * Class managing all the business object which may be needed to service the EPS.
 */
public class DatabaseAccessManager {

	private final String dbType;

	private Connection connection;

	private DALInterface databaseAbstractionLayer;

	private Map<String,Object> cache;

	public DatabaseAccessManager(JDBCConnectionInformation jdbcConnectionInformation) {
		dbType =jdbcConnectionInformation.getDbType();
	}

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
				connection.close();
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


	public synchronized DALInterface getDatabaseAbstractionLayer()
		throws InstantiationException, IllegalAccessException, ClassNotFoundException {
		if(databaseAbstractionLayer != null )
			return databaseAbstractionLayer;

        databaseAbstractionLayer = DALFactory.getDAL(dbType);
        databaseAbstractionLayer.setConnection(connection);
        return databaseAbstractionLayer;
	}

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
