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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

import com.enterprisepasswordsafe.engine.utils.DatabaseConnectionUtils;
import com.enterprisepasswordsafe.engine.utils.DateFormatter;
import com.enterprisepasswordsafe.engine.utils.PasswordUtils;
import com.enterprisepasswordsafe.proguard.ExternalInterface;

/**
 * Data access object for passwords.
 */

public class HistoricalPasswordDAO implements ExternalInterface {

    /**
     * The fields needed to create a HistoricalPassword object from a ResultSet.
     */

    public static final String HISTORICAL_PASSWORD_FIELDS = PasswordBase.PASSWORD_BASE_FIELDS
            + ", pass.dt_l";

    /**
     * The SQL statement to the last change date before a specified date for a
     * password.
     */

    private static final String GET_LAST_CHANGED_SQL = "SELECT MAX(dt_l) FROM password_history WHERE password_id = ? AND dt_l <= ?";

    /**
     * The SQL statement to the password details for a specific entry in the
     * password history table.
     */

    private static final String GET_HISTORY_ENTRY_SQL = "SELECT "
            + HISTORICAL_PASSWORD_FIELDS
            + "  FROM password_history pass"
            + " WHERE pass.password_id = ? AND pass.dt_l = ?";

    /**
     * The SQL statement to insert a password history option.
     */

    private static final String WRITE_PASSWORD_HISTORY_SQL =
        "INSERT INTO password_history(password_id, dt_l, password_data) VALUES (?,?,?)";

    /**
     * The SQL statement to insert a nullpassword history option.
     */

    private static final String WRITE_NULL_PASSWORD_HISTORY_SQL =
        "INSERT INTO password_history(password_id, dt_l) VALUES (?,?)";

	/**
	 * Private constructor to prevent instantiation
	 */

	private HistoricalPasswordDAO() {
		super();
	}

    /**
     * Writes a new history entry for a password.
     *
     * @param conn
     *            The connection to the database.
     * @param ac
     *            An access control which can update the password.

     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem encrypting the data.
     * @throws UnsupportedEncodingException
     */

    public final void writeHistoryEntry(final Password password, final AccessControl ac)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
    	long timestamp = DateFormatter.getNow();

    	try {
	    	byte[] passwordData = PasswordUtils.encrypt(password, ac);

	    	PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(WRITE_PASSWORD_HISTORY_SQL);
	        try {
	            ps.setString(1, password.getId());
	            ps.setLong  (2, timestamp);
	            ps.setBytes (3, passwordData);
	            ps.executeUpdate();
	        } finally {
	            DatabaseConnectionUtils.close(ps);
	        }
    	} catch (IOException ioe) {
    		throw new SQLException("Unable to store password history properties", ioe);
    	}
    }

    /**
     * Writes a null history entry for a password. A null entry indicates
     * history was not recorded beyond this point.
     *
     * @param conn
     *            The connection to the database
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    public final void writeNullEntry(final Password password)
        throws SQLException {
        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(WRITE_NULL_PASSWORD_HISTORY_SQL);
        try {
            ps.setString(1, password.getId());
            ps.setLong  (2, DateFormatter.getNow());

            ps.executeUpdate();
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Gets the data about an individual password for a particular time.
     *
     * @param ac The access control for accessing the password
     * @param id The ID of the password to get.
     * @param dt The timepoint at which to get the password.
     *
     * @return The Password object, or null if the user does not exist.
     *
     * @throws SQLException
     *             Thrown if there is a problem getting the password.
     */

    public HistoricalPassword getByIdForTime(final AccessControl ac, final String id, final long dt) throws SQLException {
        if (id == null) {
            return null;
        }

        long timepoint;

        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_LAST_CHANGED_SQL);
        try {
            ps.setString(1, id);
            ps.setLong  (2, dt);
            ps.setMaxRows(1);

            ResultSet rs = ps.executeQuery();
            try {
	            if (!rs.next()) {
	                return null;
	            }

	            timepoint = rs.getLong(1);
            } finally {
            	DatabaseConnectionUtils.close(rs);
            }
        } finally {
        	DatabaseConnectionUtils.close(ps);
        }

        ps = BOMFactory.getCurrentConntection().prepareStatement(GET_HISTORY_ENTRY_SQL);
        try {
            ps.setString(1, id);
            ps.setLong  (2, timepoint);
            ps.setMaxRows(1);
            ResultSet rs = ps.executeQuery();
            try {
	            if (!rs.next()) {
	            	return null;
	            }

	            HistoricalPassword password = new HistoricalPassword(rs.getString(1), rs.getBytes(2), ac, rs.getLong(3));
	        	if( password.getLocation() == null ) {
	        		return null;
	        	}
	        	return password;
            } catch(IOException ioe) {
            	throw new SQLException("Problem decoding password", ioe);
            } catch(GeneralSecurityException gse) {
            	throw new SQLException("Problem accessing password", gse);
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    //------------------------

    private static class InstanceHolder {
    	static final HistoricalPasswordDAO INSTANCE = new HistoricalPasswordDAO();
    }

    public static HistoricalPasswordDAO getInstance() {
		return InstanceHolder.INSTANCE;
    }
}
