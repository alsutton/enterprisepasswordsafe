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

public final class IPZonesTable
	extends AbstractTable{

	/**
	 * The name of this table
	 */

	private static final String TABLE_NAME = "ip_zones";

	/**
	 * The column information
	 */

	private static final ColumnSpecification ID_COLUMN = new ColumnSpecification("ip_zone_id", ColumnSpecification.TYPE_ID);
	private static final ColumnSpecification NAME_COLUMN = new ColumnSpecification("name", ColumnSpecification.TYPE_SHORT_STRING);
	private static final ColumnSpecification IP_VERSION_COLUMN = new ColumnSpecification("ip_version", ColumnSpecification.TYPE_INT);
	private static final ColumnSpecification IP_START_COLUMN = new ColumnSpecification("ip_start", ColumnSpecification.TYPE_IP_ADDRESS);
	private static final ColumnSpecification IP_END_COLUMN = new ColumnSpecification("ip_end", ColumnSpecification.TYPE_IP_ADDRESS);

	private static final ColumnSpecification[] COLUMNS = {
		ID_COLUMN, NAME_COLUMN, IP_VERSION_COLUMN, IP_START_COLUMN, IP_END_COLUMN
	};

	/**
	 * The index information
	 */

    private static final IndexSpecification ID_INDEX = new IndexSpecification("ipz_ids", TABLE_NAME, ID_COLUMN);

	private static final ColumnSpecification[] LOOKUP_INDEX_COLUMNS = { IP_VERSION_COLUMN, IP_START_COLUMN, IP_END_COLUMN};
	private static final IndexSpecification LOOKUP_INDEX = new IndexSpecification("ipz_ips", TABLE_NAME, LOOKUP_INDEX_COLUMNS);


	private static final IndexSpecification[] INDEXES = {
		ID_INDEX, LOOKUP_INDEX,
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
		}
	}

	/**
	 * Gets an instance of this table schema
	 */

	static IPZonesTable getInstance() {
		return new IPZonesTable();
	}
}
