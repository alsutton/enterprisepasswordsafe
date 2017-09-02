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

package com.enterprisepasswordsafe.engine.dbabstraction.implementations;

import java.sql.SQLException;

import com.enterprisepasswordsafe.engine.dbabstraction.AbstractDAL;
import com.enterprisepasswordsafe.engine.dbabstraction.ColumnSpecification;

/**
 * Database Abstraction Layer for PostgreSQL databases
 */

public class PostgresqlDAL
	extends AbstractDAL
{
	/**
	 * Constructor to set up translation Map.
	 */
	public PostgresqlDAL()
	{
		super();

		translationMap.put( ColumnSpecification.TYPE_LONG, "BIGINT" );
		translationMap.put( ColumnSpecification.TYPE_INT, "INTEGER" );
		translationMap.put( ColumnSpecification.TYPE_CHAR, "CHAR" );
		translationMap.put( ColumnSpecification.TYPE_ID, "VARCHAR(20)" );
		translationMap.put( ColumnSpecification.TYPE_SHORT_STRING, "VARCHAR(255)" );
		translationMap.put( ColumnSpecification.TYPE_LONG_STRING, "TEXT" );
		translationMap.put( ColumnSpecification.TYPE_BLOB, "BYTEA" );
		translationMap.put( ColumnSpecification.TYPE_MULTI_BLOB, "BYTEA" );
		translationMap.put( ColumnSpecification.TYPE_KEY, "BYTEA" );
		translationMap.put( ColumnSpecification.TYPE_IP_ADDRESS, "VARCHAR(50)" );
	}

	/**
	 * Renames a column in a given table.
	 *
	 * @param tableName The name of the table to alter.
	 * @param oldName The name of the table.
	 * @param newName The new name of the column.
	 * @param type The type for the column.
	 *
	 * @throws SQLException Thrown if there is a problem talking to the database.
	 */

	@Override
	public void renameColumn( final String tableName,
			final String oldName, final String newName, final Integer type )
		throws SQLException {
        runSQLUpdate( "ALTER TABLE " + tableName +
		              " RENAME COLUMN " + oldName +
		              " TO " + newName );
	}

}
