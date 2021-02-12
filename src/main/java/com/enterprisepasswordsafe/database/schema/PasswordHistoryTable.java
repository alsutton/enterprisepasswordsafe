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

public final class PasswordHistoryTable
	extends AbstractTable{

	/**
	 * The name of this table
	 */

	public static final String TABLE_NAME = "password_history";

	/**
	 * The column information
	 */


	private static final ColumnSpecification ID_COLUMN = new ColumnSpecification("password_id", ColumnSpecification.TYPE_ID, false, true);
	private static final ColumnSpecification TIMESTAMP_COLUMN = new ColumnSpecification("dt_l", ColumnSpecification.TYPE_LONG);
	private static final ColumnSpecification DATA_COLUMN = new ColumnSpecification("password_data", ColumnSpecification.TYPE_BLOB);


	private static final ColumnSpecification[] COLUMNS = {
		ID_COLUMN, TIMESTAMP_COLUMN, DATA_COLUMN
	};

	/**
	 * The index information
	 */

	private static final ColumnSpecification[] ID_DT_INDEX_COLUMNS = { ID_COLUMN, TIMESTAMP_COLUMN };
	private static final IndexSpecification ID_DT_INDEX =  new IndexSpecification("ph_pidts", TABLE_NAME, ID_DT_INDEX_COLUMNS);

	private static final IndexSpecification ID_INDEX = new IndexSpecification("ph_pidx", TABLE_NAME, ID_COLUMN);

	private static final IndexSpecification[] INDEXES = {
		ID_INDEX, ID_DT_INDEX
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
			createTableIfNotPresent(ID_COLUMN);
			createIfNotPresent(TIMESTAMP_COLUMN);
			createIfNotPresent(DATA_COLUMN);
		}
	}

	/**
	 * Gets an instance of this table schema
	 */

	static PasswordHistoryTable getInstance() {
		return new PasswordHistoryTable();
	}
}
