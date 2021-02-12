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

public final class IntegrationModulesScriptsTable
	extends AbstractTable {

	/**
	 * The name of this table
	 */

	private static final String TABLE_NAME = "intmodules_scripts";

	/**
	 * The column information
	 */

	private static final ColumnSpecification SCRIPT_ID_COLUMN = new ColumnSpecification("script_id", ColumnSpecification.TYPE_ID);
	private static final ColumnSpecification MODULE_ID_COLUMN = new ColumnSpecification("module_id", ColumnSpecification.TYPE_ID);
	private static final ColumnSpecification NAME__COLUMN = new ColumnSpecification("name", ColumnSpecification.TYPE_SHORT_STRING);
	private static final ColumnSpecification SCRIPT_COLUMN = new ColumnSpecification("script", ColumnSpecification.TYPE_BLOB);

	private static final ColumnSpecification[] COLUMNS = {
		SCRIPT_ID_COLUMN, MODULE_ID_COLUMN, NAME__COLUMN, SCRIPT_COLUMN
	};

	/**
	 * The index information
	 */
    private static final IndexSpecification SCRIPT_ID_INDEX = new IndexSpecification("ims_sid", TABLE_NAME, SCRIPT_ID_COLUMN);
    private static final IndexSpecification MODULE_ID_INDEX = new IndexSpecification("ims_mid", TABLE_NAME, MODULE_ID_COLUMN);

	private static final IndexSpecification[] INDEXES = {
		SCRIPT_ID_INDEX, MODULE_ID_INDEX
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
		if(schemaID < SchemaVersion.SCHEMA_201112) {
			createTableIfNotPresent(SCRIPT_ID_COLUMN);
		}
	}

	/**
	 * Gets an instance of this table schema
	 */

	static IntegrationModulesScriptsTable getInstance() {
		return new IntegrationModulesScriptsTable();
	}
}
