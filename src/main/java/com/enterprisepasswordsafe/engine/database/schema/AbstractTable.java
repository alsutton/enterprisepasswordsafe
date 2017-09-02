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

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Statement;

import com.enterprisepasswordsafe.engine.database.BOMFactory;
import com.enterprisepasswordsafe.engine.dbabstraction.ColumnSpecification;
import com.enterprisepasswordsafe.engine.dbabstraction.IndexSpecification;
import com.enterprisepasswordsafe.engine.dbabstraction.TableSpecification;
import com.enterprisepasswordsafe.engine.utils.DatabaseConnectionUtils;

public abstract class AbstractTable {

	/**
	 * Creates the table from nothing.
	 */

	public void create()
		throws SQLException {
		TableSpecification spec = new TableSpecification(getTableName());
		for(ColumnSpecification column : getAllColumns()) {
			spec.addColumnSpecification(column);
		}
		for(IndexSpecification index : getAllIndexes()) {
			spec.addIndexSpecification(index);
		}
		try {
			BOMFactory.getDatabaseAbstractionLayer().createTable(spec);
		} catch(SQLException sqle) {
			throw sqle;
		} catch(Exception ex) {
			throw new SQLException("Exception creating "+getTableName(), ex);
		}
	}

	/**
	 * Update the current schema to the latest version
	 *
	 * @param conn An auto-commiting connection to the database
	 * @param schemaID The ID of the current schema in the database.
	 */

	public abstract void updateSchema(final long schemaID)
		throws SQLException;

	/**
	 * Get the name of the table
	 */

	public abstract String getTableName();

	/**
	 * Get all of the columns in the table
	 */

	abstract ColumnSpecification[] getAllColumns();

	/**
	 * Get all of the indexes in the table
	 */

	abstract IndexSpecification[] getAllIndexes();

	/**
	 * Checks if a column exists, if it doesn't then it is created
	 */

	void createIfNotPresent(final ColumnSpecification column)
		throws SQLException {
		if(columnExists(column.getName())) {
			return;
		}

		try {
			BOMFactory.getDatabaseAbstractionLayer().addColumn(getTableName(), column);
		} catch(SQLException sqlex) {
			throw sqlex;
		} catch(Exception ex) {
			throw new SQLException("Error enabling "+column+" on "+getTableName(), ex);
		}
	}

	/**
	 * Checks if the table exists by checking for an ID column, if the ID column does not exist
	 * the table is created.
	 */

	boolean createTableIfNotPresent(final ColumnSpecification idColumn)
		throws SQLException {

		if(columnExists(idColumn.getName())) {
			return false;
		}

		try {
			create();
			return true;
		} catch(SQLException sqlex) {
			throw sqlex;
		} catch(Exception ex) {
			throw new SQLException("Error creating "+getTableName(), ex);
		}
	}


	/**
	 * Renames a column if needed
	 */

	void renameColumn(final String oldName, final ColumnSpecification columnSpecification)
		throws SQLException {
		if(!columnExists(oldName)) {
			return;
		}

		try {
			BOMFactory.
				getDatabaseAbstractionLayer().
					renameColumn(
							getTableName(),
							oldName,
							columnSpecification.getName(),
							columnSpecification.getType() );
		} catch(SQLException sqle) {
			throw sqle;
		} catch(Exception ex) {
			throw new SQLException("Error during column rename.", ex);
		}
	}


	/**
	 * Check to see if a column exists
	 *
	 * @param name The name of the column to check for.
     *
     * @return true if it exists, false if not.
	 */

	private boolean columnExists(final String name)
		throws SQLException {
		StringBuilder query = new StringBuilder(128);
		query.append("select ");
		query.append(name);
		query.append(" from ");
		query.append(getTableName());

		Connection conn = BOMFactory.getCurrentConntection();
		Statement stmt = null;
		try {
			stmt = conn.createStatement();
			ResultSet rs = null;
			try {
				rs = stmt.executeQuery(query.toString());

				ResultSetMetaData rsm = rs.getMetaData();
				for(int i = 1 ; i <= rsm.getColumnCount() ; i++) {
					if(name.equalsIgnoreCase(rsm.getColumnName(i))) {
						return true;
					}
				}

				return false;
			} catch(SQLException sqle) {
				return false;
			} finally {
				DatabaseConnectionUtils.close(rs);
			}
		} catch(SQLException sqle) {
			return false;
		} finally {
			DatabaseConnectionUtils.close(stmt);
		}
	}
}
