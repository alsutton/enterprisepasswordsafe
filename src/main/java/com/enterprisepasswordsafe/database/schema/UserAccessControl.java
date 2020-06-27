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

package com.enterprisepasswordsafe.database.schema;

import java.sql.SQLException;

public final class UserAccessControl
	extends AbstractTable{

	/**
	 * The name of this table
	 */

	private static final String TABLE_NAME = "user_access_control";

	/**
	 * The column information
	 */


	private static final ColumnSpecification USER_ID_COLUMN = new ColumnSpecification("user_id", ColumnSpecification.TYPE_ID, false, true);
	private static final ColumnSpecification ITEM_ID_COLUMN = new ColumnSpecification("item_id", ColumnSpecification.TYPE_ID, false, true);
	private static final ColumnSpecification MKEY_COLUMN = new ColumnSpecification("mkey", ColumnSpecification.TYPE_BLOB);
	private static final ColumnSpecification RKEY_COLUMN = new ColumnSpecification("rkey", ColumnSpecification.TYPE_BLOB);

	private static final ColumnSpecification[] COLUMNS = {
		USER_ID_COLUMN, ITEM_ID_COLUMN, RKEY_COLUMN, MKEY_COLUMN
	};

	/**
	 * The index information
	 */

	private static final ColumnSpecification[] ID_INDEX_COLUMNS = { USER_ID_COLUMN, ITEM_ID_COLUMN  };
	private static final IndexSpecification ID_INDEX = new IndexSpecification("uac_uidiid", TABLE_NAME, ID_INDEX_COLUMNS);

	private static final IndexSpecification ITEM_ID_INDEX = new IndexSpecification("uac_iid", TABLE_NAME, ITEM_ID_COLUMN);
	private static final IndexSpecification USER_ID_INDEX = new IndexSpecification("uac_uid", TABLE_NAME, USER_ID_COLUMN);

	private static final IndexSpecification[] INDEXES = {
		ID_INDEX, ITEM_ID_INDEX, USER_ID_INDEX
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
			createIfNotPresent(MKEY_COLUMN);
			createIfNotPresent(RKEY_COLUMN);
			createTableIfNotPresent(USER_ID_COLUMN);
			renameColumn(ITEM_ID_COLUMN);
		}
	}

	/**
	 * Gets an instance of this table schema
	 */

	protected static UserAccessControl getInstance() {
		return new UserAccessControl();
	}
}
