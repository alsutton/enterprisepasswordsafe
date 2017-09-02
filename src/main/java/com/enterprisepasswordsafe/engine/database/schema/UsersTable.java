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

package com.enterprisepasswordsafe.engine.database.schema;

import java.sql.*;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.enterprisepasswordsafe.engine.database.BOMFactory;
import com.enterprisepasswordsafe.engine.dbabstraction.ColumnSpecification;
import com.enterprisepasswordsafe.engine.dbabstraction.IndexSpecification;
import com.enterprisepasswordsafe.engine.utils.HexConverter;

public final class UsersTable
	extends AbstractTable{

	/**
	 * The name of this table
	 */

	private static final String TABLE_NAME = "application_users";

	/**
	 * The column information
	 */

	private static final ColumnSpecification ID_COLUMN = new ColumnSpecification("user_id", ColumnSpecification.TYPE_ID, true, true);
	private static final ColumnSpecification USER_NAME_COLUMN = new ColumnSpecification("user_name", ColumnSpecification.TYPE_SHORT_STRING, true, true);
	private static final ColumnSpecification USER_PASSWORD_COLUMN = new ColumnSpecification("user_pass_b", ColumnSpecification.TYPE_BLOB, false, false);
	private static final ColumnSpecification FULL_NAME_COLUMN = new ColumnSpecification("full_name", ColumnSpecification.TYPE_LONG_STRING);
	private static final ColumnSpecification EMAIL_COLUMN = new ColumnSpecification("email", ColumnSpecification.TYPE_LONG_STRING);
	private static final ColumnSpecification ACCESS_KEY_COLUMN = new ColumnSpecification("akey", ColumnSpecification.TYPE_BLOB, false, false);
	private static final ColumnSpecification ADMIN_ACCESS_KEY_COLUMN = new ColumnSpecification("aakey", ColumnSpecification.TYPE_BLOB, false, false);
	private static final ColumnSpecification LAST_LOGIN_COLUMN = new ColumnSpecification("last_login_l", ColumnSpecification.TYPE_LONG);
	private static final ColumnSpecification LOGIN_ATTEMPTS_COLUMN = new ColumnSpecification("login_attempts", ColumnSpecification.TYPE_INT);
	private static final ColumnSpecification AUTH_SOURCE_COLUMN = new ColumnSpecification("auth_source", ColumnSpecification.TYPE_ID);
	private static final ColumnSpecification DISABLED_COLUMN = new ColumnSpecification("disabled", ColumnSpecification.TYPE_CHAR);
	private static final ColumnSpecification PWD_LAST_CHANGED_COLUMN = new ColumnSpecification("pwd_last_changed_l", ColumnSpecification.TYPE_LONG);

	private static final ColumnSpecification[] COLUMNS = {
		ID_COLUMN, USER_NAME_COLUMN, USER_PASSWORD_COLUMN, FULL_NAME_COLUMN, EMAIL_COLUMN,
		ACCESS_KEY_COLUMN, ADMIN_ACCESS_KEY_COLUMN, LAST_LOGIN_COLUMN, LOGIN_ATTEMPTS_COLUMN,
		AUTH_SOURCE_COLUMN, DISABLED_COLUMN, PWD_LAST_CHANGED_COLUMN
	};

	/**
	 * The index information
	 */

	private static final IndexSpecification ID_INDEX = new IndexSpecification("au_uid", TABLE_NAME, ID_COLUMN);

	private static final IndexSpecification[] INDEXES = {
		ID_INDEX
	};

	/**
	 * Get the name of this table
	 */

	@Override
	public String getTableName() {
		return TABLE_NAME;
	}

	/**
	 * Get all of the columns in the table
	 */

	@Override
	ColumnSpecification[] getAllColumns() {
		return COLUMNS;
	}

	/**
	 * Get all of the indexes in the table
	 */

	@Override
	IndexSpecification[] getAllIndexes() {
		return INDEXES;
	}

	/**
	 * Update the current schema to the latest version
	 */

	@Override
	public void updateSchema(final long schemaID)
		throws SQLException {
		if(schemaID >= SchemaVersion.CURRENT_SCHEMA)
			return;

		if(schemaID < SchemaVersion.SCHEMA_201112) {
			createIfNotPresent(ACCESS_KEY_COLUMN);
			createIfNotPresent(ADMIN_ACCESS_KEY_COLUMN);
			createIfNotPresent(LAST_LOGIN_COLUMN);
			createIfNotPresent(PWD_LAST_CHANGED_COLUMN);
			createIfNotPresent(FULL_NAME_COLUMN);
			createIfNotPresent(EMAIL_COLUMN);
			createIfNotPresent(AUTH_SOURCE_COLUMN);
		}

        if(schemaID < SchemaVersion.SCHEMA_201212) {
            createIfNotPresent(USER_PASSWORD_COLUMN);
            try {
                convertPasswordStorage();
            } catch(SQLException e) {
                // Ignore, can be thrown if the old storage column does not exist.
            }

            createIfNotPresent(ACCESS_KEY_COLUMN);
            try {
                convertAccessKeyStorage();
            } catch(SQLException e) {
                // Ignore, can be thrown if the old storage column does not exist.
            }

            createIfNotPresent(ADMIN_ACCESS_KEY_COLUMN);
            try {
                convertAdminAccessKeyStorage();
            } catch(SQLException e) {
                // Ignore, can be thrown if the old storage column does not exist.
            }

            createIfNotPresent(LAST_LOGIN_COLUMN);
            createIfNotPresent(PWD_LAST_CHANGED_COLUMN);
            try {
                convertPasswordLastChangedStorage();
            } catch(SQLException e) {
                // Ignore, can be thrown if the old storage column does not exist.
            }
        }
	}

    /**
     * Converts the password storage from the old style into the new one.
     */

    private void convertPasswordStorage()
        throws SQLException {
        Connection conn = BOMFactory.getCurrentConntection();
        Map<String, byte[]> updatedPasswords = new HashMap<String, byte[]>();

        Statement statement = conn.createStatement();
        try {
            ResultSet rs = statement.executeQuery("SELECT user_id, user_pass FROM application_users WHERE user_pass <> '!'");
            try {
                while(rs.next()) {
                    String id = rs.getString(1);
                    String password = rs.getString(2);

                    byte[] converted;
                    int saltSeparator = password.indexOf('*');
                    if(saltSeparator == -1) {
                        byte[] passwordBytes = HexConverter.toBytes(password);
                        converted = new byte[passwordBytes.length+1];
                        converted[0] = 1;
                        System.arraycopy(passwordBytes, 0, converted, 1, passwordBytes.length);
                    } else {
                        String salt = password.substring(0, saltSeparator);
                        byte[] saltBytes = HexConverter.toBytes(salt);

                        String hash = password.substring(saltSeparator+1);
                        byte[] hashBytes = HexConverter.toBytes(hash);

                        converted = new byte[2+saltBytes.length+hashBytes.length];
                        converted[0] = 2;
                        converted[1] = (byte) saltBytes.length;
                        System.arraycopy(converted, 2, saltBytes, 0, saltBytes.length);
                        System.arraycopy(converted, 2+saltBytes.length, hashBytes, 0, hashBytes.length);
                    }
                    updatedPasswords.put(id, converted);
                }
            } finally {
                rs.close();
            }
        } finally {
            statement.close();
        }

        PreparedStatement ps = conn.prepareStatement("UPDATE application_users SET user_pass = '!', user_pass_b = ? WHERE user_id = ?");
        try {
            for(Map.Entry<String, byte[]> thisEntry : updatedPasswords.entrySet()) {
                ps.setBytes(1, thisEntry.getValue());
                ps.setString(2, thisEntry.getKey());
                ps.executeUpdate();
            }
        } finally {
            ps.close();
        }
    }

    /**
     * Convert access key storage to the new format
     */

    private void convertAccessKeyStorage()
        throws SQLException{
        Connection conn = BOMFactory.getCurrentConntection();
        Map<String, byte[]> updatedPasswords = new HashMap<String, byte[]>();

        Statement statement = conn.createStatement();
        try {
            ResultSet rs = statement.executeQuery("SELECT user_id, access_key FROM application_users WHERE access_key <> '!'");
            try {
                while(rs.next()) {
                    String id = rs.getString(1);
                    String key = rs.getString(2);

                    byte[] converted;
                    if( key.startsWith("refid") ) {
                        converted = getKeyById(conn, key.substring(6));
                    } else {
                        converted = HexConverter.toBytes(key);
                    }

                    updatedPasswords.put(id, converted);
                }
            } finally {
                rs.close();
            }
        } finally {
            statement.close();
        }

        PreparedStatement ps = conn.prepareStatement("UPDATE application_users SET access_key = '!', akey = ? WHERE user_id = ?");
        try {
            for(Map.Entry<String, byte[]> thisEntry : updatedPasswords.entrySet()) {
                ps.setBytes(1, thisEntry.getValue());
                ps.setString(2, thisEntry.getKey());
                ps.executeUpdate();
            }
        } finally {
            ps.close();
        }
    }

    /**
     * Convert admin access key storage to the new format
     */

    private void convertAdminAccessKeyStorage()
            throws SQLException {
        Connection conn = BOMFactory.getCurrentConntection();
        Map<String, byte[]> updatedPasswords = new HashMap<String, byte[]>();

        Statement statement = conn.createStatement();
        try {
            ResultSet rs = statement.executeQuery("SELECT user_id, admin_access_key FROM application_users WHERE admin_access_key <> '!'");
            try {
                while(rs.next()) {
                    String id = rs.getString(1);
                    String key = rs.getString(2);

                    byte[] converted;
                    if( key.startsWith("refid") ) {
                        converted = getKeyById(conn, key.substring(6));
                    } else {
                        converted = HexConverter.toBytes(key);
                    }

                    updatedPasswords.put(id, converted);
                }
            } finally {
                rs.close();
            }
        } finally {
            statement.close();
        }

        PreparedStatement ps = conn.prepareStatement("UPDATE application_users SET admin_access_key = '!', aakey = ? WHERE user_id = ?");
        try {
            for(Map.Entry<String, byte[]> thisEntry : updatedPasswords.entrySet()) {
                ps.setBytes(1, thisEntry.getValue());
                ps.setString(2, thisEntry.getKey());
                ps.executeUpdate();
            }
        } finally {
            ps.close();
        }
    }

    /**
     * Get the byte array for a particular key.
     *
     * @param keyId The ID of the key to get.
     *
     * @return The byte[] for the key, or null if it does not exist.
     */

    private byte[] getKeyById(final Connection conn, final String keyId)
            throws SQLException {
        PreparedStatement ps = conn.prepareStatement("SELECT key_data FROM keystore WHERE key_id = ?");
        ps.setMaxRows(1);
        try {
            ps.setString(1, keyId);
            ResultSet rs = ps.executeQuery();
            try {
                if( rs.next() ) {
                    return rs.getBytes(1);
                }
                return null;
            } finally {
                rs.close();
            }
        } finally {
            ps.close();
        }
    }

    /**
     * Convert admin access key storage to the new format
     */

    private void convertPasswordLastChangedStorage()
            throws SQLException {
        Connection conn = BOMFactory.getCurrentConntection();
        Map<String, Long> updatedPasswords = new HashMap<String, Long>();

        Calendar cal = Calendar.getInstance();
        cal.set(Calendar.HOUR_OF_DAY, 0);
        cal.set(Calendar.MINUTE, 0);
        cal.set(Calendar.SECOND, 0);
        cal.set(Calendar.MILLISECOND, 0);

        Statement statement = conn.createStatement();
        try {
            ResultSet rs = statement.executeQuery("SELECT user_id, pwd_last_changed FROM application_users WHERE pwd_last_changed <> '!'");
            try {
                while(rs.next()) {
                    String id = rs.getString(1);
                    String date = rs.getString(2);

                    try {
                        cal.set(Calendar.YEAR, Integer.parseInt(date.substring(0, 4)));
                        cal.set(Calendar.MONTH, Integer.parseInt(date.substring(4, 6)));
                        cal.set(Calendar.DAY_OF_MONTH, Integer.parseInt(date.substring(6,8)));
                    } catch(NumberFormatException e) {
                        Logger.getAnonymousLogger().log(Level.SEVERE, "Problem converting date "+date, e);
                    }

                    updatedPasswords.put(id, cal.getTimeInMillis());
                }
            } finally {
                rs.close();
            }
        } finally {
            statement.close();
        }

        PreparedStatement ps = conn.prepareStatement("UPDATE application_users SET pwd_last_changed = '!', pwd_last_changed_l = ? WHERE user_id = ?");
        try {
            for(Map.Entry<String, Long> thisEntry : updatedPasswords.entrySet()) {
                ps.setLong(1, thisEntry.getValue());
                ps.setString(2, thisEntry.getKey());
                ps.executeUpdate();
            }
        } finally {
            ps.close();
        }
    }

    /**
	 * Gets an instance of this table schema
	 */

	protected static UsersTable getInstance() {
		return new UsersTable();
	}
}
