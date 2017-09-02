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

public final class IntegrationModulesConfigurationTable
	extends AbstractTable {

	/**
	 * The name of this table
	 */

	private static final String TABLE_NAME = "intmodules_conf";

	/**
	 * The column information
	 */

	private static final ColumnSpecification ID_COLUMN = new ColumnSpecification("script_id", ColumnSpecification.TYPE_ID);
	private static final ColumnSpecification PASSWORD_ID_COLUMN = new ColumnSpecification("password_id", ColumnSpecification.TYPE_ID);
	private static final ColumnSpecification PARAMETER_NAME_COLUMN = new ColumnSpecification("parameter_name", ColumnSpecification.TYPE_SHORT_STRING);
	private static final ColumnSpecification PARAMETER_VALUE_COLUMN = new ColumnSpecification("parameter_value", ColumnSpecification.TYPE_LONG_STRING);

	private static final ColumnSpecification[] COLUMNS = {
		ID_COLUMN, PASSWORD_ID_COLUMN, PARAMETER_NAME_COLUMN, PARAMETER_VALUE_COLUMN
	};

	/**
	 * The index information
	 */
    private static final IndexSpecification ID_INDEX = new IndexSpecification("imc_pid", TABLE_NAME, PASSWORD_ID_COLUMN);

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
		if(schemaID < SchemaVersion.SCHEMA_201112) {
			createTableIfNotPresent(ID_COLUMN);
		}
	}

	/**
	 * Gets an instance of this table schema
	 */

	protected static IntegrationModulesConfigurationTable getInstance() {
		return new IntegrationModulesConfigurationTable();
	}
}
