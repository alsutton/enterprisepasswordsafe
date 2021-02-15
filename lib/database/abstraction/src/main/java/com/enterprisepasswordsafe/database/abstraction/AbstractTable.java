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

package com.enterprisepasswordsafe.database.abstraction;

import com.enterprisepasswordsafe.database.abstraction.vendorspecific.DALInterface;

import java.sql.*;
import java.util.Arrays;
import java.util.List;

public abstract class AbstractTable {

	private DALInterface databaseAbstractionLayer;

	public AbstractTable(DALInterface databaseAbstractionLayer) {
		this.databaseAbstractionLayer = databaseAbstractionLayer;
	}

	public void create(DALInterface databaseAbstractionLayer)
		throws SQLException {
		TableSpecification spec =
				ImmutableTableSpecification.builder()
					.name(getTableName())
					.columnSpecifications(getAllColumns())
					.indexSpecifications(getAllIndexes())
					.build();
		try {
			databaseAbstractionLayer.createTable(spec);
		} catch(SQLException sqle) {
			throw sqle;
		} catch(Exception ex) {
			throw new SQLException("Exception creating "+getTableName(), ex);
		}
	}

	public abstract void updateSchema(final long schemaID)
		throws SQLException;

	public abstract String getTableName();

	abstract List<ColumnSpecification> getAllColumns();

	abstract List<IndexSpecification> getAllIndexes();

	public void createIfNotPresent(final Connection conn, final ColumnSpecification column)
		throws SQLException {
		if(columnExists(conn, column.getName())) {
			return;
		}

		try {
			databaseAbstractionLayer.addColumn(getTableName(), column);
		} catch(SQLException sqlex) {
			throw sqlex;
		} catch(Exception ex) {
			throw new SQLException("Error enabling "+column.getName()+" on "+getTableName(), ex);
		}
	}

	boolean createTableIfNotPresent(final Connection conn, final ColumnSpecification idColumn)
		throws SQLException {

		if(columnExists(conn, idColumn.getName())) {
			return false;
		}

		try {
			create(databaseAbstractionLayer);
			return true;
		} catch(SQLException sqlex) {
			throw sqlex;
		} catch(Exception ex) {
			throw new SQLException("Error creating "+getTableName(), ex);
		}
	}

	void renameColumn(final Connection conn, final ColumnSpecification columnSpecification)
		throws SQLException {
		if(!columnExists(conn, "password_id")) {
			return;
		}

		try {
			databaseAbstractionLayer.renameColumn(getTableName(),
                    "password_id", columnSpecification.getName(), columnSpecification.getType() );
		} catch(SQLException sqlex) {
			throw sqlex;
		} catch(Exception ex) {
			throw new SQLException("Error during column rename.", ex);
		}
	}

	private boolean columnExists(Connection conn, final String name) {
		StringBuilder query = new StringBuilder(128);
		query.append("select ");
		query.append(name);
		query.append(" from ");
		query.append(getTableName());

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
