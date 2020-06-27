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
import com.enterprisepasswordsafe.database.schema.IndexSpecification;
import com.enterprisepasswordsafe.database.vendorspecific.AbstractDAL;

import java.sql.SQLException;

/**
 * Database Abstraction Layer for Oracle databases
 */
public class OracleDAL
	extends AbstractDAL
{
	/**
	 * Constructor to set up translation Map.
	 */
	public OracleDAL()
	{
		super();

		translationMap.put( ColumnSpecification.TYPE_LONG, "NUMBER" );
		translationMap.put( ColumnSpecification.TYPE_INT, "NUMBER" );
		translationMap.put( ColumnSpecification.TYPE_CHAR, "CHAR" );
		translationMap.put( ColumnSpecification.TYPE_ID, "VARCHAR2(20)" );
		translationMap.put( ColumnSpecification.TYPE_SHORT_STRING, "VARCHAR2(255)" );
		translationMap.put( ColumnSpecification.TYPE_LONG_STRING, "VARCHAR2(3072)" );
		translationMap.put( ColumnSpecification.TYPE_BLOB, "LONG RAW" );
		translationMap.put( ColumnSpecification.TYPE_MULTI_BLOB, "RAW(2000)" );
		translationMap.put( ColumnSpecification.TYPE_KEY, "RAW(1024)" );
		translationMap.put( ColumnSpecification.TYPE_IP_ADDRESS, "VARCHAR2(50)" );
		
		setUsesColumnOnAdd(false);
	}
	
	/**
	 * Oracle bitches about trying to create indexes on columns it's already
	 * created an internal index for. Therefore we trash these exceptions.
	 * 
	 * @param specification The index specification.
	 * 
	 * @throws SQLException Thrown if there is a problem with the database.
	 */
	
	public void addIndex( final IndexSpecification specification )
		throws SQLException
	{
		try
		{
			super.addIndex( specification );
		}
		catch( SQLException sqle )
		{
			if( sqle.getErrorCode() != 1408 )
			{
				throw sqle;
			}
		}
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

	public void renameColumn( final String tableName, 
			final String oldName, final String newName, final Integer type ) 
		throws SQLException {
        runSQLUpdate( "ALTER TABLE " + tableName +
                      " RENAME COLUMN " + oldName +
                      " TO " + newName );
	}

}
