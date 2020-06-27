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
import java.sql.SQLException;

import com.enterprisepasswordsafe.engine.Repositories;
import com.enterprisepasswordsafe.engine.configuration.JDBCConnectionInformation;
import com.enterprisepasswordsafe.engine.dbabstraction.DALInterface;

/**
 * Factory for handling and releasing business object managers.
 */

public final class BOMFactory {

	//---------------------------------------

	private static ThreadLocal<DatabaseAccessManager> localInstance =  new ThreadLocal<>();

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

		JDBCConnectionInformation connectionInformation;
		try {
			connectionInformation = Repositories.jdbcConfigurationRepository.load();
		} catch (GeneralSecurityException e) {
			return null;
		}

		int retries = 3;
		while(retries-- > 0) {
			currentInstance = new DatabaseAccessManager(connectionInformation);
			localInstance.set(currentInstance);
			return currentInstance;
		}

		return null;
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
	 * @throws ClassNotFoundException
	 * @throws IllegalAccessException
	 * @throws InstantiationException
	 */

	public static DALInterface getDatabaseAbstractionLayer()
		throws InstantiationException, IllegalAccessException, ClassNotFoundException {
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
