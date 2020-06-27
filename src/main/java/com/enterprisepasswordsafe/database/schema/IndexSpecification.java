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

import java.util.ArrayList;
import java.util.List;

/**
 * Represnetation of an index on a specific database column.
 */

public final class IndexSpecification {

	/**
	 * The name of this index.
	 */

	private final String indexName;

	/**
	 * The table on which the index is placed.
	 */

	private final String tableName;

	/**
	 * The list of columns indexed.
	 */

	private final List<String> columns;

	/**
	 * Whether or not this index contains unique values.
	 */

	boolean uniqueOnly = false;

	/**
	 * Construct the index representation.
	 *
	 * @param indexName An identifier for this index.
	 * @param table The table on which the index is placed.
	 * @param columns The columns involved in the index.
	 */

	public IndexSpecification(final String indexName, final String table, final List<String> columns )
	{
		this.indexName = indexName;
		this.tableName = table;
		this.columns = columns;
	}

	/**
	 * Construct the index representation.
	 *
	 * @param indexName An identifier for this index.
	 * @param table The table on which the index is placed.
	 * @param columnArray The columns involved in the index.
	 */

	public IndexSpecification(final String indexName, final String table, final String[] columnArray )
	{
		this(indexName, table, new ArrayList<>());
		for(String column : columnArray) {
			addColumn(column);
		}
	}

	/**
	 * Construct the index representation.
	 *
	 * @param indexName An identifier for this index.
	 * @param table The table on which the index is placed.
	 * @param columnArray The columns involved in the index.
	 */

	public IndexSpecification(final String indexName, final String table, final ColumnSpecification[] columnArray )
	{
		this(indexName, table, new ArrayList<>());
		for(ColumnSpecification column : columnArray) {
			addColumn(column.getName());
		}
	}

	/**
	 * Constructor for a single column index.
	 *
	 * @param indexName An identifier for this index.
	 * @param table The name of the table on which the index should be placed.
	 * @param columnName The name of the column to index.
	 */

	public IndexSpecification(String indexName,  String table, String columnName )
	{
		this(indexName, table, new ArrayList<>());
		addColumn(columnName);
	}

	/**
	 * Constructor for a single column index.
	 *
	 * @param indexName An identifier for this index.
	 * @param table The name of the table on which the index should be placed.
	 * @param column The name of the column to index.
	 */

	public IndexSpecification(final String indexName,final String table, final ColumnSpecification column )
	{
		this(indexName, table, column.getName());
	}

	/**
	 * Constructor to allow later addition of columns.
	 *
	 * @param indexName An identifier for this index.
	 * @param table The name of the table on which the index should be placed.
	 */

	public IndexSpecification(String indexName,  String table )
	{
		this(indexName, table, new ArrayList<>());
	}

	/**
	 * Add a column to the index.
	 *
	 * @param columnName The name of the column to add to the index.
	 */

	public void addColumn( String columnName )
	{
		columns.add( columnName );
	}

	/**
	 * Get the list of columns.
	 *
	 * @return The list of columns in this index.
	 */

	public List<String> getColumns()
	{
		return columns;
	}

	/**
	 * Set index to contain unique or non-unique. The default is non-unique.
	 *
	 * @param unique True if the index should only contain unique values, false if not.
	 */

	public void setUnique( boolean unique )
	{
		uniqueOnly = unique;
	}

	/**
	 * Gets whether or not this index should contain only unique values.
	 *
	 * @return true if the index should contain unique values, false if not.
	 */

	public boolean isUnique()
	{
		return uniqueOnly;
	}

	/**
	 * Get the identifier name of this index.
	 *
	 * @return The identifier name of this index.
	 */

	public String getIndexName()
	{
		return indexName;
	}

	/**
	 * Get the name of the table this index should be placed on.
	 *
	 * @return the name of the table the index should be placed on.
	 */

	public String getTableName()
	{
		return tableName;
	}
}
