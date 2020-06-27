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

package com.enterprisepasswordsafe.database.vendorspecific.implementations;

import com.enterprisepasswordsafe.database.schema.ColumnSpecification;
import com.enterprisepasswordsafe.database.vendorspecific.AbstractDAL;

import java.sql.SQLException;

/**
 * Database Abstraction Layer for HSQLDB databases
 */

public class ApacheDerbyDAL
	extends AbstractDAL
{
	/**
	 * Constructor to set up translation Map.
	 */
	public ApacheDerbyDAL()
	{
		super();

		translationMap.put( ColumnSpecification.TYPE_LONG, "BIGINT" );
		translationMap.put( ColumnSpecification.TYPE_INT, "INTEGER" );
		translationMap.put( ColumnSpecification.TYPE_CHAR, "CHAR" );
		translationMap.put( ColumnSpecification.TYPE_ID, "VARCHAR(20)" );
		translationMap.put( ColumnSpecification.TYPE_SHORT_STRING, "VARCHAR(255)" );
		translationMap.put( ColumnSpecification.TYPE_LONG_STRING, "VARCHAR(3072)" );
		translationMap.put( ColumnSpecification.TYPE_BLOB, "BLOB" );
		translationMap.put( ColumnSpecification.TYPE_MULTI_BLOB, "BLOB" );
		translationMap.put( ColumnSpecification.TYPE_KEY, "BLOB" );
		translationMap.put( ColumnSpecification.TYPE_IP_ADDRESS, "VARCHAR(50)" );
	}

	public String addCreationURLParameters(final String url) {
		if(url.contains("create=true")) {
			return url;
		}
		char separator = (url.indexOf(';') == -1) ? ';' : '&';
		return url + separator + "create=true";
	}

	/**
	 * Renames a column in a given table.
	 *
	 * @param tableName The name of the table to alter.
	 * @param oldName The name of the table.
	 * @param newName The new name of the column.
	 * @param type The type for the column.
	 *
	 * @throws java.sql.SQLException Thrown if there is a problem talking to the database.
	 */

	@Override
	public void renameColumn( final String tableName,
			final String oldName, final String newName, final Integer type )
		throws SQLException {
		runSQLUpdate("RENAME COLUMN "+tableName+"."+oldName+" TO "+newName);
	}

}
