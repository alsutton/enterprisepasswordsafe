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

package com.enterprisepasswordsafe.engine.configuration;

import com.enterprisepasswordsafe.engine.dbabstraction.SupportedDatabase;
import com.enterprisepasswordsafe.engine.dbpool.DatabasePool;
import com.enterprisepasswordsafe.proguard.ExternalInterface;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

/**
 * Object responsible for storing the JDBC connection details and creating
 * connections to the database.
 *
 */
public class JDBCConfiguration implements ExternalInterface {
	/**
	 * The AES key used to store the password.
	 */

	private static final byte[] PASSWORD_AES_KEY = { 84, -54, 102, -106, 30,
			-63, 98, 125, 52, 22, 34, 44, -39, 86, 11, -120 };

	/**
	 * The list of database types.
	 */

	public static final String[] DATABASE_TYPES;
	static {
		List<String> databaseTypes = new ArrayList<>();
		for(SupportedDatabase database : SupportedDatabase.values()) {
			if(database.isSupportDeprecated()) {
				continue;
			}
			databaseTypes.add(database.getType());
		}
		DATABASE_TYPES = databaseTypes.toArray(new String[databaseTypes.size()]);
	}

    /**
     * A lock to ensure that only one request is verifying the JDBC
     * Configuration at any time.
     */

    private static final Object VERIFICATION_LOCK = new Object();

    /**
	 * The Database type.
	 */

	private String dbType;

	/**
	 * The JDBC Driver class.
	 */

	private String driver;

	/**
	 * The JDBC access URL.
	 */

	private String url;

	/**
	 * The JDBC access username.
	 */

	private String username;

	/**
	 * The JDBC access password.
	 */

	private String password;

	/**
	 * The name of the parameter used to store the database type.
	 */

	private static final String DB_TYPE_PARAMETER = "eps_db.type";

	/**
	 * The name of the parameter used to store the JDBC driver class.
	 */

	private static final String DRIVER_PARAMETER = "eps_jdbc.driver";

	/**
	 * The name of the parameter used to store the JDBC url.
	 */

	private static final String URL_PARAMETER = "eps_jdbc.url";

	/**
	 * The name of the parameter used to store the JDBC username.
	 */

	private static final String USERNAME_PARAMETER = "eps_jdbc.username";

	/**
	 * The name of the parameter used to store the JDBC password.
	 */

	private static final String PASSWORD_PARAMETER = "eps_jdbc.password";

	/**
	 * The name of the encrypted parameter used to store the JDBC password.
	 */

	private static final String ENCRYPTED_PASSWORD_PARAMETER = "eps_jdbc.password.encrypted";

	/**
	 * The parameter to indicate auto initialisation.
	 */

	private static final String AUTO_INIT = "eps_jdbc.autoinit";

	/**
	 * The preferences for the system
	 */

	private Preferences prefs;

	/**
	 * Load the JDBC configuration from the preferences store.
	 *
	 * @param configurationClass
	 *            The class holding the configuration data.
	 */
	public void loadConfiguration(Class<?> configurationClass)
			throws ClassNotFoundException, SQLException, GeneralSecurityException {
		prefs = Preferences.userRoot();
		dbType = prefs.get(DB_TYPE_PARAMETER, null);
		if (dbType == null) {
			prefs = Preferences.systemNodeForPackage(configurationClass);
			dbType = prefs.get(DB_TYPE_PARAMETER, null);
		}
		driver = prefs.get(DRIVER_PARAMETER, null);
		url = prefs.get(URL_PARAMETER, null);
		username = prefs.get(USERNAME_PARAMETER, null);
		byte[] passwordBytes = prefs.getByteArray(ENCRYPTED_PASSWORD_PARAMETER,
				null);
		if (passwordBytes == null) {
			password = prefs.get(PASSWORD_PARAMETER, null);
			if (password != null) {
				prefs.putByteArray(ENCRYPTED_PASSWORD_PARAMETER,
						encryptPasswordText(password));
				prefs.remove(PASSWORD_PARAMETER);
			}
		} else {
			password = decryptPasswordText(passwordBytes);
		}
	}

	/**
	 * Store the preferences.
	 *
	 * @throws ClassNotFoundException Thrown if the driver class isn't available.
	 */

	public void store()
			throws GeneralSecurityException, ClassNotFoundException,
			BackingStoreException, SQLException {
		prefs = Preferences.userRoot();
		prefs.put(DB_TYPE_PARAMETER, dbType);
		prefs.put(DRIVER_PARAMETER, driver);
		prefs.put(URL_PARAMETER, url);
		prefs.put(USERNAME_PARAMETER, username);
		prefs.putByteArray(ENCRYPTED_PASSWORD_PARAMETER,
				encryptPasswordText(password));
		prefs.flush();
	}

	/**
	 * Encrypt a text string using the AES key.
	 *
	 * @param text The text to encrypt.
     *
	 * @return The byte array of encrypted data.
	 */

	private byte[] encryptPasswordText(String text)
			throws GeneralSecurityException {
		SecretKey cryptoKey = new SecretKeySpec(PASSWORD_AES_KEY, "AES");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, cryptoKey);

		return cipher.doFinal(text.getBytes());
	}

	/**
	 * Decrypt a text string using the AES key.
	 *
	 * @param data The encrypted password.
     *
	 * @return The password.
	 */

	private String decryptPasswordText(byte[] data)
			throws GeneralSecurityException {
		SecretKey cryptoKey = new SecretKeySpec(PASSWORD_AES_KEY, "AES");
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, cryptoKey);

		byte[] original = cipher.doFinal(data);
		return new String(original);
	}

	/**
	 * Tests if autoinit has been set
	 *
	 * @return true if the auto init is set, false if not.
	 */

	public boolean isAutoInitSet() {
		String autoInitFlag = prefs.get(AUTO_INIT, "N");
		return (autoInitFlag.toLowerCase().charAt(0) == 'y');
	}

	/**
	 * Clear the autoinit flag.
	 */

	public void cleanAutoInit() {
		prefs.remove(AUTO_INIT);
	}

    /**
     * Verifies the current JDBCConfiguration is valid. If it is valid, and
     * hasn't been previously checked then we should also install any missing
     * database features.
     *
     * @return true if it is valid, false if not.
     */

    public boolean isValid()
            throws SQLException, ClassNotFoundException {
        synchronized (VERIFICATION_LOCK) {
            return hasValidParameters() && isConfigurationUsable();
        }
    }

	private boolean isConfigurationUsable() {
		try (DatabasePool pool = new DatabasePool(this)) {
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

	public boolean hasValidParameters() {
		if (driver == null || url == null || username == null || password == null) {
			return false;
		}

		try {
			Class.forName(driver);
		} catch (ClassNotFoundException e) {
			Logger.getAnonymousLogger().log(Level.SEVERE, "Error testing database.", e);
			return false;
		}

		return true;
	}

	/**
	 * Creates a string representation of this object.
	 *
	 * @return A string representation holding this objects details.
	 */

	@Override
	public String toString() {
        return  "DB Type: " + dbType +
                ", Driver: " + driver +
                ", URL: " + url +
                ", Username: " + username +
                ", Password: " + password;
	}

	/**
	 * Set the database type.
	 *
	 * @param newDBType
	 *            The database type.
	 */
	public void setDatabaseType(final String newDBType) {
		dbType = newDBType;
	}

	/**
	 * Set the JDBC driver driver.
	 *
	 * @param newDriver
	 *            The database driver class name.
	 */
	public void setDriver(final String newDriver) {
		driver = newDriver;
	}

	/**
	 * Set the JDBC URL.
	 *
	 * @param newURL
	 *            The database url.
	 */
	public void setURL(final String newURL) {
		url = newURL;
	}

	/**
	 * Set the JDBC username to access the database using.
	 *
	 * @param newUsername
	 *            The username to use.
	 */
	public void setUsername(final String newUsername) {
		username = newUsername;
	}

	/**
	 * Set the JDBC password to access the database with.
	 *
	 * @param newPassword
	 *            The password to use.
	 */
	public void setPassword(final String newPassword) {
		password = newPassword;
	}

	/**
	 * Generate the Hash code for this object.
	 *
	 * @return The hash code for the object.
	 */

	@Override
	public int hashCode() {
		return dbType.hashCode() | driver.hashCode() | url.hashCode()
				| username.hashCode() | password.hashCode();
	}

	/**
	 * Test for equality between this and another object.
	 *
	 * @param otherObject
	 *            The object to compare this to.
	 *
	 * @return true if the objects are equal, false if not.
	 */

	@Override
	public boolean equals(final Object otherObject) {
		if(otherObject == null) {
			return false;
		}

		if (!(otherObject instanceof JDBCConfiguration)) {
			return false;
		}

		JDBCConfiguration otherConfig = (JDBCConfiguration) otherObject;
		return dbType.equals(otherConfig.dbType)
				&& driver.equals(otherConfig.driver)
				&& url.equals(otherConfig.url)
				&& username.equals(otherConfig.username)
				&& password.equals(otherConfig.password);
	}

	/**
	 * Get the driver for this configuration.
	 *
	 * @return The driver for this configuration.
	 */

	public String getDriver() {
		return driver;
	}

	/**
	 * Get the database type for this connection.
	 *
	 * @return The database type.
	 */

	public String getDBType() {
		return dbType;
	}

	/**
	 * Get the URL for the database connection.
	 *
	 * @return The JDBC URL.
	 */

	public String getURL() {
		return url;
	}

	/**
	 * Get the username for the JDBC connection.
	 *
	 * @return The JDBC username.
	 */

	public String getUsername() {
		return username;
	}

	/**
	 * Get the password for the JDBC connection.
	 *
	 * @return The password for the JDBC connection.
	 */

	public String getPassword() {
		return password;
	}

	/**
	 * Factory method to instanciate the correct JDBC configuration object.
	 *
	 * @return a JDBCConfiguration class.
	 */

	public static JDBCConfiguration getConfiguration()
		throws ConfigurationRetrievalException {
		if (forcedConfiguration != null) {
			return forcedConfiguration;
		}

		try {
			JDBCConfiguration jdbcConfiguration = new JDBCConfiguration();
			jdbcConfiguration.loadConfiguration(JDBCConfiguration.class);
			return jdbcConfiguration;
		} catch(ClassNotFoundException | SQLException | GeneralSecurityException e) {
			throw new ConfigurationRetrievalException(e);
		}
	}

	/**
	 * Workaround to avoid the need to use powermockito.
	 *
	 * TODO: Refactor so this is unnecessary.
	 */

	static JDBCConfiguration forcedConfiguration = null;

	static void force(JDBCConfiguration configuration) {
		forcedConfiguration = configuration;
	}

	public static class ConfigurationRetrievalException extends RuntimeException {
		ConfigurationRetrievalException(Exception ex) {
			super(ex);
		}
	}
}
