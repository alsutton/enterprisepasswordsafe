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
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;

import com.enterprisepasswordsafe.engine.database.BOMFactory;
import com.enterprisepasswordsafe.engine.database.HierarchyNode;
import com.enterprisepasswordsafe.engine.dbabstraction.ColumnSpecification;
import com.enterprisepasswordsafe.engine.dbabstraction.IndexSpecification;
import com.enterprisepasswordsafe.engine.utils.DatabaseConnectionUtils;
import com.enterprisepasswordsafe.engine.utils.IDGenerator;

public final class HierarchyTable
	extends AbstractTable{

	/**
     * SQL To get the password information neccessary for migration.
     */

    private static final String GET_MIGRATION_INFO_SQL = "select password_id, location from passwords order by location";

    /**
     * The SQL statement to write a new node to the database.
     */

    private static final String INSERT_NODE_SQL =
            "INSERT INTO hierarchy( name, parent_id, type, node_id ) "
            + "            VALUES (    ?,         ?,    ?,       ? ) ";

	/**
	 * The name of this table
	 */

	private static final String TABLE_NAME = "hierarchy";

	/**
	 * Column information
	 */


	private static final ColumnSpecification ID_COLUMN = new ColumnSpecification("node_id", ColumnSpecification.TYPE_SHORT_STRING);
	private static final ColumnSpecification NAME_COLUMN = new ColumnSpecification("name", ColumnSpecification.TYPE_LONG_STRING);
	private static final ColumnSpecification PARENT_ID_COLUMN = new ColumnSpecification("parent_id", ColumnSpecification.TYPE_SHORT_STRING);
	private static final ColumnSpecification TYPE_COLUMN = new ColumnSpecification("type", ColumnSpecification.TYPE_INT);

    private static final ColumnSpecification[] COLUMNS = {
    	ID_COLUMN, NAME_COLUMN, PARENT_ID_COLUMN, TYPE_COLUMN
    };

    /**
     * Index information
     */


    private static final IndexSpecification ID_INDEX = new IndexSpecification("hi_nid", TABLE_NAME, ID_COLUMN);
    private static final IndexSpecification PARENT_ID_INDEX = new IndexSpecification("hi_pid", TABLE_NAME, PARENT_ID_COLUMN);
    private static final IndexSpecification TYPE_INDEX = new IndexSpecification("hi_typ", TABLE_NAME, TYPE_COLUMN);

    private static final IndexSpecification[] INDEXES = {
    	ID_INDEX, PARENT_ID_INDEX, TYPE_INDEX
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
		if(schemaID < SchemaVersion.SCHEMA_201112) {
			if(createTableIfNotPresent(ID_COLUMN)) {
				migrateLocations();
			}
		}
	}

    /**
     * Code to migrate existing locations to be hierarchy positions.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws ClassNotFoundException
     * @throws IllegalAccessException
     * @throws InstantiationException
     */

    private void migrateLocations()
    	throws SQLException {
    	PreparedStatement ps = null;
        Statement stmt = null;
        ResultSet rs = null;
        try {
        	Connection conn = BOMFactory.getCurrentConntection();
            ps = conn.prepareStatement(INSERT_NODE_SQL);
            stmt = conn.createStatement();
            rs = stmt.executeQuery(GET_MIGRATION_INFO_SQL);
            String lastLocation = null;
            String currentParentId = HierarchyNode.ROOT_NODE_ID;
            while (rs.next()) {
                String name = rs.getString(2).intern();

                if (lastLocation != name) {
                	String newId = IDGenerator.getID();
                	int idx = 1;
                	ps.setString(idx++, name);
                	ps.setString(idx++, HierarchyNode.ROOT_NODE_ID);
                	ps.setInt(idx++, HierarchyNode.CONTAINER_NODE);
                	ps.setString(idx++, newId);
                	ps.executeUpdate();

                    currentParentId = newId;
                    lastLocation = name;
                }

                String passwordId = rs.getString(1);

            	int idx = 1;
            	ps.setString(idx++, passwordId);
            	ps.setString(idx++, currentParentId);
            	ps.setInt(idx++, HierarchyNode.OBJECT_NODE);
            	ps.setString(idx++, IDGenerator.getID());
            	ps.executeUpdate();
            }
        } catch(SQLException sqle) {
        	throw sqle;
        } catch(Exception ex) {
        	throw new SQLException("Error migrating password locations", ex);
        } finally {
            DatabaseConnectionUtils.close(rs);
            DatabaseConnectionUtils.close(stmt);
            DatabaseConnectionUtils.close(ps);
        }
    }

	/**
	 * Gets an instance of this table schema
	 */

	protected static HierarchyTable getInstance() {
		return new HierarchyTable();
	}
}
