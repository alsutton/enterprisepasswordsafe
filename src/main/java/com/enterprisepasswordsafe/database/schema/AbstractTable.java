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

import com.enterprisepasswordsafe.database.BOMFactory;

import java.sql.*;

public abstract class AbstractTable {

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

	public abstract void updateSchema(final long schemaID)
		throws SQLException;

	public abstract String getTableName();

	abstract ColumnSpecification[] getAllColumns();

	abstract IndexSpecification[] getAllIndexes();

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

	void renameColumn(final String oldName, final ColumnSpecification columnSpecification)
		throws SQLException {
		if(!columnExists(oldName)) {
			return;
		}

		try {
			BOMFactory.getDatabaseAbstractionLayer().renameColumn(getTableName(),
				oldName, columnSpecification.getName(), columnSpecification.getType() );
		} catch(SQLException sqlex) {
			throw sqlex;
		} catch(Exception ex) {
			throw new SQLException("Error during column rename.", ex);
		}
	}

	private boolean columnExists(final String name)
		throws SQLException {
		StringBuilder query = new StringBuilder(128);
		query.append("select ");
		query.append(name);
		query.append(" from ");
		query.append(getTableName());

		Connection conn = BOMFactory.getCurrentConntection();
		try(Statement stmt = conn.createStatement()) {
			try(ResultSet rs = stmt.executeQuery(query.toString())) {
				ResultSetMetaData rsm = rs.getMetaData();
				for(int i = 1 ; i <= rsm.getColumnCount() ; i++) {
					if(name.equalsIgnoreCase(rsm.getColumnName(i))) {
						return true;
					}
				}

				return false;
			}
		} catch(SQLException sqle) {
			return false;
		}
	}
}
