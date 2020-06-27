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

package com.enterprisepasswordsafe.database.vendorspecific;

import com.enterprisepasswordsafe.database.BOMFactory;
import com.enterprisepasswordsafe.database.schema.ColumnSpecification;
import com.enterprisepasswordsafe.database.schema.IndexSpecification;
import com.enterprisepasswordsafe.database.schema.TableSpecification;

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Hashtable;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Interface implemented by all Database Abstraction Layer classes.
 */

public abstract class AbstractDAL
	implements DALInterface
{
	/**
	 * Type translation map, maps the specified type to a database specific
	 * type.
	 */

	protected Map<Integer,String> translationMap = new Hashtable<>();

	/**
	 * Whether or not the database expects the word column in the add clause.
	 */

	private  boolean usesColumnOnAdd = true;

	/**
	 * Whether or not the database supports the unique constraint.
	 */

	protected boolean supportsUnique = true;

	/**
	 * The connection to the database
	 */
	protected Connection connection;

	public String addCreationURLParameters(final String url) {
		return url;
	}

	/**
	 * Set the database connection.
	 *
	 * @param theConnection The connection to the database.
	 */

	@Override
	public void setConnection( final Connection theConnection ) {
		connection = theConnection;
	}

	/**
	 * Gets the current database connection.
	 *
	 * @return A java.sql.Connection object.
	 */

	@Override
	public Connection getConnection()
		throws SQLException {
		if(connection == null) {
			connection = BOMFactory.getCurrentConntection();
		}

		return connection;
	}

	/**
	 * Places the code to start a table creation into a StringBuffer
	 *
	 * @param buffer The buffer to use.
	 * @param spec The specification holding the table definition.
	 */

	protected void startTableDefinition( final StringBuffer buffer, final TableSpecification spec )
	{
		buffer.append( "create table " );
		buffer.append( spec.getName() );
		buffer.append( '(' );
	}

	/**
	 * Places the code to end a table creation into a StringBuffer
	 *
	 * @param buffer The buffer to use.
	 */

	protected void endTableDefinition( final StringBuffer buffer )
	{
		buffer.append( ')' );
	}

	/**
	 * Places the code to add a column to a table definition.
	 *
	 * @param buffer The buffer to use.
	 * @param spec The specifications for the columns in the table.
	 */

	protected void addColumnDefinition( final StringBuffer buffer, final ColumnSpecification spec )
	{
		buffer.append( spec.getName() );
		buffer.append( ' ' );
		buffer.append( translationMap.get(spec.getType()) );

		if( spec.getRejectNulls() )
		{
			buffer.append( " NOT NULL" );
		}

		if( spec.getUniqueOnly() && supportsUnique )
		{
			buffer.append( " UNIQUE" );
		}
	}

	/**
	 * Creates a table in the database.
	 *
	 * @param spec The database specification.
	 *
	 * @throws SQLException If there is problem with the database.
	 */

	@Override
	public void createTable( final TableSpecification spec )
		throws SQLException
	{
        StringBuilder sqlBuffer = new StringBuilder("select * from ");
		sqlBuffer.append(spec.getName());
		try (Statement stmt = getConnection().createStatement()) {
			try (ResultSet rs = stmt.executeQuery(sqlBuffer.toString())) {
				if (rs.next()) {
					Logger.getAnonymousLogger().log(Level.WARNING, "Warning; Attempt to create " + spec.getName() + " blocked, table already exists.");
					return;
				}
			}
		} catch (SQLException sqle) {
			// SQL Exception is good, it means the table doesn't exist.
		}


		StringBuffer creationCommand = new StringBuffer( 1024 );

		startTableDefinition( creationCommand, spec );

		for(ColumnSpecification thisSpec : spec.getColumnSpecifications()) {
			addColumnDefinition( creationCommand, thisSpec );
			creationCommand.append( ',' );
		}
		creationCommand.deleteCharAt(creationCommand.length()-1);


		endTableDefinition( creationCommand );

		runSQLUpdate(creationCommand.toString());

		// Create all of the indexes.
		for(IndexSpecification indexSpec : spec.getIndexSpecifications()) {
		    addIndex(indexSpec );
		}
	}

	/**
	 * Adds a column to a given table
	 *
	 * @param tableName The name of the table to alter.
	 * @param spec The specification of the column to add.
	 *
	 * @throws SQLException Thrown if there is a problem adding the column.
	 */

	@Override
	public void addColumn( final String tableName,
			final ColumnSpecification spec )
		throws SQLException
	{
		StringBuffer commandBuffer = new StringBuffer( 512 );

		commandBuffer.append( "ALTER TABLE " );
		commandBuffer.append( tableName );
		commandBuffer.append( " ADD " );

		if( getUsesColumnOnAdd() )
		{
			commandBuffer.append( "COLUMN " );
		}

		addColumnDefinition( commandBuffer, spec );

		runSQLUpdate(commandBuffer.toString());
	}

	/**
	 * Creates an index of a set of columns.
	 *
	 * @param specification The index specification.
	 *
	 * @throws SQLException Thrown if there is a problem with the database.
	 */

	@Override
	public void addIndex( final IndexSpecification specification)
		throws SQLException
	{
		StringBuilder commandBuffer = new StringBuilder( 512 );

		commandBuffer.append( "CREATE ");
		if( specification.isUnique() )
		{
			commandBuffer.append( "UNIQUE ");
		}
		commandBuffer.append( "INDEX ");
		commandBuffer.append( specification.getIndexName() );
		commandBuffer.append( " ON ");
		commandBuffer.append( specification.getTableName() );
		commandBuffer.append( " (" );

		for(String columnName : specification.getColumns() ) {
			commandBuffer.append( columnName );
			commandBuffer.append( ',' );
		}

		commandBuffer.deleteCharAt(commandBuffer.length()-1);
		commandBuffer.append( ')' );

		runSQLUpdate(commandBuffer.toString());
	}

	/**
	 * Send a query to the database
	 *
	 * @param sql The SQL to run.
	 *
	 * @return true if there were any results.
	 *
	 * @throws SQLException Thrown if there is a problem talking to the database.
	 */

	@Override
	public boolean runSQLQuery( final String sql )
		throws SQLException {
		try(Statement stmt = getConnection().createStatement()) {
			stmt.setMaxRows(1);
			try(ResultSet rs = stmt.executeQuery( sql )) {
				return rs.next();
			}
		}
	}

	/**
	 * Send a command to the database
	 *
	 * @param sql The SQL to run.
	 *
	 * @throws SQLException Thrown if there is a problem talking to the database.
	 */

	@Override
	public void runSQLUpdate( String sql )
		throws SQLException {
		try(Statement stmt = getConnection().createStatement()) {
			stmt.executeUpdate( sql );
		}
	}

	/**
	 * Get whether or not the DAL needs add column or not.
	 *
	 * @return true if the DAL needs "add column", false if not.
	 */
	public boolean getUsesColumnOnAdd() {
		return usesColumnOnAdd;
	}

	/**
	 * Set whether or not the DAL needs add column or not.
	 *
	 * @param newUsesColumnOnAdd true if the DAL needs "add column", false if not.
	 */
	public void setUsesColumnOnAdd(boolean newUsesColumnOnAdd) {
		usesColumnOnAdd = newUsesColumnOnAdd;
	}

}
