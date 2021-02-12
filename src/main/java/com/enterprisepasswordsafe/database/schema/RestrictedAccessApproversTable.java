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

public final class RestrictedAccessApproversTable
	extends AbstractTable{

	/**
	 * The name of this table
	 */

	private static final String TABLE_NAME = "ra_approver_lists";

	/**
	 * Column information
	 */

	private static final ColumnSpecification ID_COLUMN = new ColumnSpecification("list_id", ColumnSpecification.TYPE_ID, false, true);
	private static final ColumnSpecification USER_ID_COLUMN = new ColumnSpecification("user_id", ColumnSpecification.TYPE_ID);
	private static final ColumnSpecification APPROVAL_STATE_COLUMN = new ColumnSpecification("approval_state", ColumnSpecification.TYPE_CHAR);
	private static final ColumnSpecification DT_COLUMN = new ColumnSpecification("dt_l", ColumnSpecification.TYPE_LONG);

    private static final ColumnSpecification[] COLUMNS = {
    	ID_COLUMN, USER_ID_COLUMN, APPROVAL_STATE_COLUMN, DT_COLUMN
    };

    /**
     * Index information
     */

    private static final IndexSpecification ID_INDEX =  new IndexSpecification("ral_lid", TABLE_NAME, ID_COLUMN);

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
			createTableIfNotPresent(ID_COLUMN);
			createIfNotPresent(DT_COLUMN);
		}
	}

	/**
	 * Gets an instance of this table schema
	 */

	static RestrictedAccessApproversTable getInstance() {
		return new RestrictedAccessApproversTable();
	}
}
