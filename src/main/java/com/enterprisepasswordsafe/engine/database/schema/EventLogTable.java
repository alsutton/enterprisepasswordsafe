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

import java.sql.SQLException;

import com.enterprisepasswordsafe.engine.dbabstraction.ColumnSpecification;
import com.enterprisepasswordsafe.engine.dbabstraction.IndexSpecification;

public final class EventLogTable
	extends AbstractTable{

	/**
	 * The name of this table
	 */

	private static final String TABLE_NAME = "event_log";

	/**
	 * Column information
	 */

	private static final ColumnSpecification USER_ID_COLUMN = new ColumnSpecification("user_id", ColumnSpecification.TYPE_ID, false, true);
	private static final ColumnSpecification ITEM_ID_COLUMN = new ColumnSpecification("item_id", ColumnSpecification.TYPE_ID);
	private static final ColumnSpecification ITEM_DT_COLUMN = new ColumnSpecification("item_dt_l", ColumnSpecification.TYPE_LONG);
	private static final ColumnSpecification DT_COLUMN = new ColumnSpecification("dt_l", ColumnSpecification.TYPE_LONG);
	private static final ColumnSpecification EVENT_COLUMN = new ColumnSpecification("event", ColumnSpecification.TYPE_LONG_STRING);
	private static final ColumnSpecification STAMP_COLUMN = new ColumnSpecification("stamp_b", ColumnSpecification.TYPE_BLOB);


    private static final ColumnSpecification[] COLUMNS = {
    	USER_ID_COLUMN, ITEM_ID_COLUMN, ITEM_DT_COLUMN, DT_COLUMN, EVENT_COLUMN, STAMP_COLUMN
    };

    /**
     * Index information
     */

    private static final IndexSpecification DT_INDEX = new IndexSpecification("el_dt", TABLE_NAME, DT_COLUMN);
    private static final IndexSpecification UID_INDEX = new IndexSpecification("el_uid", TABLE_NAME, USER_ID_COLUMN);
    private static final IndexSpecification IID_INDEX = new IndexSpecification("el_iid", TABLE_NAME, ITEM_ID_COLUMN);

    private static final IndexSpecification[] INDEXES = {
    	DT_INDEX, UID_INDEX, IID_INDEX
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

		if(schemaID < SchemaVersion.SCHEMA_201212) {
			createIfNotPresent(ITEM_DT_COLUMN);
			createIfNotPresent(DT_COLUMN);
			createIfNotPresent(STAMP_COLUMN);
		}
	}

	/**
	 * Gets an instance of this table schema
	 */

	protected static EventLogTable getInstance() {
		return new EventLogTable();
	}
}
