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

import com.enterprisepasswordsafe.engine.accesscontrol.AccessControl;
import com.enterprisepasswordsafe.engine.utils.DateFormatter;
import com.enterprisepasswordsafe.engine.utils.PasswordUtils;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class HistoricalPasswordDAO {

    public static final String HISTORICAL_PASSWORD_FIELDS = PasswordBase.PASSWORD_BASE_FIELDS + ", pass.dt_l";

    private static final String GET_LAST_CHANGED_SQL = "SELECT MAX(dt_l) FROM password_history WHERE password_id = ? AND dt_l <= ?";

    private static final String GET_HISTORY_ENTRY_SQL = "SELECT "
            + HISTORICAL_PASSWORD_FIELDS
            + "  FROM password_history pass"
            + " WHERE pass.password_id = ? AND pass.dt_l = ?";

    private static final String WRITE_PASSWORD_HISTORY_SQL =
        "INSERT INTO password_history(password_id, dt_l, password_data) VALUES (?,?,?)";

    private static final String WRITE_NULL_PASSWORD_HISTORY_SQL =
        "INSERT INTO password_history(password_id, dt_l) VALUES (?,?)";

	private HistoricalPasswordDAO() {
		super();
	}

    public final void writeHistoryEntry(final Password password, final AccessControl ac)
            throws SQLException, GeneralSecurityException {
    	long timestamp = DateFormatter.getNow();

    	try {
	    	byte[] passwordData = PasswordUtils.encrypt(password, ac);
	        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(WRITE_PASSWORD_HISTORY_SQL)) {
	            ps.setString(1, password.getId());
	            ps.setLong  (2, timestamp);
	            ps.setBytes (3, passwordData);
	            ps.executeUpdate();
	        }
    	} catch (IOException ioe) {
    		throw new SQLException("Unable to store password history properties", ioe);
    	}
    }

    public final void writeNullEntry(final Password password)
        throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(WRITE_NULL_PASSWORD_HISTORY_SQL)) {
            ps.setString(1, password.getId());
            ps.setLong  (2, DateFormatter.getNow());

            ps.executeUpdate();
        }
    }

    public HistoricalPassword getByIdForTime(final AccessControl ac, final String id, final long dt) throws SQLException {
        if (id == null) {
            return null;
        }

        long timepoint;
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_LAST_CHANGED_SQL)) {
            ps.setString(1, id);
            ps.setLong  (2, dt);
            ps.setMaxRows(1);
            try(ResultSet rs = ps.executeQuery()) {
	            if (!rs.next()) {
	                return null;
	            }

	            timepoint = rs.getLong(1);
            }
        }

        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_HISTORY_ENTRY_SQL)) {
            ps.setString(1, id);
            ps.setLong  (2, timepoint);
            ps.setMaxRows(1);
            try(ResultSet rs = ps.executeQuery()) {
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
            }
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
