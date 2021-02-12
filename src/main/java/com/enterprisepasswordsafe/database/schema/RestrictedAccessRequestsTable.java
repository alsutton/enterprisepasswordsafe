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

public final class RestrictedAccessRequestsTable
	extends AbstractTable{

	/**
	 * The name of this table
	 */

	private static final String TABLE_NAME = "ra_requests";

	/**
	 * Column information
	 */

	private static final ColumnSpecification REQUEST_ID_COLUMN = new ColumnSpecification("request_id", ColumnSpecification.TYPE_ID, false, true);
	private static final ColumnSpecification ITEM_ID_COLUMN = new ColumnSpecification("item_id", ColumnSpecification.TYPE_ID);
	private static final ColumnSpecification REQUESTER_ID_COLUMN = new ColumnSpecification("requester_id", ColumnSpecification.TYPE_ID);
	private static final ColumnSpecification APPROVERS_LIST_ID_COLUMN = new ColumnSpecification("approvers_list_id", ColumnSpecification.TYPE_ID);
	private static final ColumnSpecification REQUEST_DT_COLUMN = new ColumnSpecification("request_dt_l", ColumnSpecification.TYPE_LONG);
	private static final ColumnSpecification VIEW_DT_COLUMN = new ColumnSpecification("viewed_dt_l", ColumnSpecification.TYPE_LONG);
	private static final ColumnSpecification REASON_COLUMN = new ColumnSpecification("reason", ColumnSpecification.TYPE_LONG_STRING);

    private static final ColumnSpecification[] COLUMNS = {
    	REQUEST_ID_COLUMN, ITEM_ID_COLUMN, REQUESTER_ID_COLUMN, APPROVERS_LIST_ID_COLUMN,
    	REQUEST_DT_COLUMN, VIEW_DT_COLUMN, REASON_COLUMN
    };

    /**
     * Index information
     */

    private static final ColumnSpecification[] REQUEST_INDEX_COLUMNS = { ITEM_ID_COLUMN, REQUESTER_ID_COLUMN };
    private static final IndexSpecification REQUEST_INDEX =  new IndexSpecification("rar_iidrid", TABLE_NAME, REQUEST_INDEX_COLUMNS);

    private static final IndexSpecification ID_INDEX =  new IndexSpecification("rar_rid", TABLE_NAME, REQUEST_ID_COLUMN);

    private static final IndexSpecification[] INDEXES = {
    	ID_INDEX, REQUEST_INDEX
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
			createTableIfNotPresent(REQUEST_ID_COLUMN);
			renameColumn(ITEM_ID_COLUMN);
		}
	}

	/**
	 * Gets an instance of this table schema
	 */

	static RestrictedAccessRequestsTable getInstance() {
		return new RestrictedAccessRequestsTable();
	}
}
