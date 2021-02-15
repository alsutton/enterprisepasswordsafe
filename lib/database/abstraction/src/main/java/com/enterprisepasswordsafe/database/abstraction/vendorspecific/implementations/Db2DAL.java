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

package com.enterprisepasswordsafe.database.abstraction.vendorspecific.implementations;

import com.enterprisepasswordsafe.database.abstraction.ColumnSpecification;
import com.enterprisepasswordsafe.database.abstraction.vendorspecific.AbstractDAL;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * Database Abstraction Layer for DB2 databases
 */

public class Db2DAL
	extends AbstractDAL
{
	/**
	 * Constructor to set up translation Map.
	 */
	public Db2DAL(Connection conn)
	{
		super(conn);

		translationMap.put( ColumnSpecification.Type.LONG, "BIGINT" );
		translationMap.put( ColumnSpecification.Type.INT, "INTEGER" );
		translationMap.put( ColumnSpecification.Type.CHAR, "CHAR" );
		translationMap.put( ColumnSpecification.Type.ID, "VARCHAR(20)" );
		translationMap.put( ColumnSpecification.Type.SHORT_STRING, "VARCHAR(255)" );
		translationMap.put( ColumnSpecification.Type.LONG_STRING, "VARCHAR(3072)" );
		translationMap.put( ColumnSpecification.Type.BLOB, "BLOB(2M)" );
		translationMap.put( ColumnSpecification.Type.MULTI_BLOB, "BLOB(2M)" );
		translationMap.put( ColumnSpecification.Type.KEY, "BLOB(1K)" );
		translationMap.put( ColumnSpecification.Type.IP_ADDRESS, "VARCHAR(50)" );
		
		setUsesColumnOnAdd(false);
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
			final String oldName, final String newName, final ColumnSpecification.Type type )
		throws SQLException {
		runSQLUpdate("ALTER TABLE " + tableName + " RENAME COLUMN " +
				oldName + " TO " + newName);
	}

}
