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
import java.util.ArrayList;
import java.util.List;

import com.enterprisepasswordsafe.engine.database.BOMFactory;
import com.enterprisepasswordsafe.engine.dbabstraction.ColumnSpecification;
import com.enterprisepasswordsafe.engine.dbabstraction.IndexSpecification;
import com.enterprisepasswordsafe.engine.utils.HexConverter;

public final class MembershipTable
	extends AbstractTable{

	/**
	 * The name of this table
	 */

	private static final String TABLE_NAME = "membership";

	/**
	 * Column information
	 */

	private static final ColumnSpecification GROUP_ID_COLUMN = new ColumnSpecification("group_id", ColumnSpecification.TYPE_ID, false, true);
	private static final ColumnSpecification USER_ID_COLUMN = new ColumnSpecification("user_id", ColumnSpecification.TYPE_ID, false, true);
	private static final ColumnSpecification ACCESS_KEY_COLUMN = new ColumnSpecification("akey", ColumnSpecification.TYPE_BLOB, false, false);


    private static final ColumnSpecification[] COLUMNS = {
    	GROUP_ID_COLUMN, USER_ID_COLUMN, ACCESS_KEY_COLUMN
    };

    /**
     * Index information
     */


    private static final ColumnSpecification[] COMBINED_ID_INDEX_COLUMNS = { GROUP_ID_COLUMN, USER_ID_COLUMN };
    private static final IndexSpecification COMBINED_ID_INDEX = new IndexSpecification("mb_giduid", TABLE_NAME, COMBINED_ID_INDEX_COLUMNS);

    private static final IndexSpecification USER_ID_INDEX = new IndexSpecification("mb_uididx", TABLE_NAME, USER_ID_COLUMN);
    private static final IndexSpecification GROUP_ID_INDEX = new IndexSpecification("mb_gididx", TABLE_NAME, GROUP_ID_COLUMN);

    private static final IndexSpecification[] INDEXES = {
    	COMBINED_ID_INDEX, USER_ID_INDEX, GROUP_ID_INDEX
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
        if(schemaID < SchemaVersion.SCHEMA_201212) {
            createIfNotPresent(ACCESS_KEY_COLUMN);
            try {
                convertAccessKeyStorage();
            } catch(SQLException sqle) {
                // Ignore, can be thrown if the th old column doesn't exist
            }
        }
    }

    /**
     * Convert access key storage to the new format
     */

    private void convertAccessKeyStorage()
            throws SQLException{
        Connection conn = BOMFactory.getCurrentConntection();
        List<UpdatedMembership> updates = new ArrayList<UpdatedMembership>(1024);

        Statement statement = conn.createStatement();
        try {
            ResultSet rs = statement.executeQuery("SELECT user_id, group_id, access_key FROM membership WHERE access_key <> '!'");
            try {
                while(rs.next()) {
                    String userId = rs.getString(1);
                    String groupId = rs.getString(2);
                    String key = rs.getString(3);

                    byte[] converted;
                    if( key.startsWith("refid") ) {
                        converted = getKeyById(conn, key.substring(6));
                    } else {
                        converted = HexConverter.toBytes(key);
                    }

                    updates.add(new UpdatedMembership(userId, groupId, converted));
                }
            } finally {
                rs.close();
            }
        } finally {
            statement.close();
        }

        PreparedStatement ps = conn.prepareStatement("UPDATE membership SET access_key = '!', akey = ? WHERE user_id = ? AND group_id = ?");
        try {
            for(UpdatedMembership thisEntry : updates) {
                ps.setBytes(1, thisEntry.mKey);
                ps.setString(2, thisEntry.mUserId);
                ps.setString(3, thisEntry.mGroupId);
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
	 * Gets an instance of this table schema
	 */

	protected static MembershipTable getInstance() {
		return new MembershipTable();
	}

    /**
     * Class holding updated membership information
     */

    private static final class UpdatedMembership {
        final String mUserId;
        final String mGroupId;
        final byte[] mKey;

        UpdatedMembership(final String userId, final String groupId, final byte[] key) {
            mUserId = userId;
            mGroupId = groupId;
            mKey = key;
        }
    }
}
