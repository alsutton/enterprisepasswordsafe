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

package com.enterprisepasswordsafe.database;

import com.enterprisepasswordsafe.database.vendorspecific.DALInterface;
import com.enterprisepasswordsafe.engine.Repositories;
import com.enterprisepasswordsafe.engine.configuration.JDBCConnectionInformation;

import java.lang.reflect.InvocationTargetException;
import java.sql.Connection;
import java.sql.SQLException;

/**
 * Factory for handling and releasing business object managers.
 */

public final class BOMFactory {

	//---------------------------------------

	private static final ThreadLocal<DatabaseAccessManager> localInstance =  new ThreadLocal<>();

	/**
	 * Gets an instance.
	 *
	 * @return a usable instance.
	 */

	public static DatabaseAccessManager getInstance() {
		DatabaseAccessManager currentInstance = localInstance.get();
		if(currentInstance != null) {
			return currentInstance;
		}

		JDBCConnectionInformation connectionInformation  = Repositories.jdbcConfigurationRepository.get();
		currentInstance = new DatabaseAccessManager(connectionInformation);
		localInstance.set(currentInstance);
		return currentInstance;
	}

	/**
	 * Gets the current JDBC database connection object
	 */

	public static Connection getCurrentConntection()
		throws SQLException {
		DatabaseAccessManager databaseAccessManager = getInstance();
		return databaseAccessManager.getConnection();
	}

	/**
	 * Gets the database abstraction layer currently in use
	 */

	public static DALInterface getDatabaseAbstractionLayer()
			throws InstantiationException, IllegalAccessException, NoSuchMethodException, InvocationTargetException {
		return getInstance().getDatabaseAbstractionLayer();
	}

	/**
	 * Clears the current instance.
	 */

	public static void closeCurrent() {
		DatabaseAccessManager currentInstance = localInstance.get();
		if(currentInstance == null) {
			return;
		}

		currentInstance.close();
	}
}
