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

package com.enterprisepasswordsafe.engine.dbabstraction;

import com.enterprisepasswordsafe.proguard.ExternalInterface;

import java.sql.Connection;
import java.sql.SQLException;

/**
 * Interface implemented by all Database Abstraction Layer classes.
 */

public interface DALInterface extends ExternalInterface
{
	/**
	 * Add any parameters needed when creating a new database to
	 * the database URL.
	 */

	public String addCreationURLParameters(final String url);

	/**
	 * Set the connection to use.
	 *
	 * @param conn The connection to the database.
	 */

	public void setConnection( Connection conn );

	/**
	 * Get the direct connection to the database.
	 */

	public Connection getConnection()
		throws SQLException;

	/**
	 * Creates a table in the database.
	 *
	 * @param spec The database specification.
	 *
	 * @throws SQLException Thrown if there is a problem talking to the database.
	 */

	public void createTable( TableSpecification spec )
		throws SQLException;

	/**
	 * Adds a column to a given table
	 *
	 * @param tableName The name of the table to alter.
	 * @param spec The specification of the column to add.
	 *
	 * @throws SQLException Thrown if there is a problem talking to the database.
	 */

	public void addColumn( String tableName, ColumnSpecification spec )
		throws SQLException;

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

	public void renameColumn( String tableName, String oldName,
			String newName, Integer type )
		throws SQLException;

	/**
	 * Creates an index of a set of columns.
	 *
	 * @param specification The index specification.
	 *
	 * @throws SQLException Thrown if there is a problem with the database.
	 */

	public void addIndex( IndexSpecification specification )
		throws SQLException;

	/**
	 * Run some a raw SQL query.
	 *
	 * @param sql The SQL to run.
	 *
	 * @return true if a record was returned. False if not.
	 *
	 * @throws SQLException Thrown if there is a problem with the database.
	 */

	public boolean runSQLQuery( String sql )
		throws SQLException;

	/**
	 * Run a raw SQL update.
	 *
	 * @param sql The SQL to run.
	 *
	 * @throws SQLException Thrown if there is a problem with the database.
	 */

	public void runSQLUpdate( String sql )
		throws SQLException;
}
