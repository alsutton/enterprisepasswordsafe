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
 * Class handling the mapping of database types to implementations.
 */

public class TableSpecification
{
	/**
	 * The name of the table.
	 */

	private String m_name;

	/**
	 * The columns in the table.
	 */

	private List<ColumnSpecification> m_columnSpecs;

	/**
	 * The indices in the table
	 */
	
	private List<IndexSpecification> m_indexes;
	
	/**
	 * Constructor.
	 *
	 * @param tableName The name of the table.
	 */

	public TableSpecification( String tableName )
	{
		this( tableName, new ArrayList<>() );
	}

	/**
	 * Constructor.
	 *
	 * @param tableName The name of the table.
	 * @param columnSpecs The specifications for the columns of the table.
	 */

	public TableSpecification( String tableName, List<ColumnSpecification> columnSpecs )
	{
		m_name = tableName;
		m_columnSpecs = columnSpecs;
		m_indexes = new ArrayList<>();
	}

	/**
	 * Get the name of the table,
	 *
	 * @return Get the name of the table.
	 */

	public String getName()
	{
		return m_name;
	}

	/**
	 * Add a column specification to this table specification
	 *
	 * @param spec The column specification to add..
	 */

	public void addColumnSpecification( ColumnSpecification spec )
	{
		m_columnSpecs.add( spec );
	}

	/**
	 * Get an Iterator over the column specifications
	 *
	 * @return The Iterator of column specifications.
	 */

	public List<ColumnSpecification> getColumnSpecifications()
	{
		return m_columnSpecs;
	}

	/**
	 * Add an index specification to this table specification.
	 *
	 * @param spec The column specification to add.
	 */

	public void addIndexSpecification( IndexSpecification spec )
	{
		m_indexes.add( spec );
	}

	/**
	 * Get an Iterator over the index specifications
	 *
	 * @return The Iterator of index specifications.
	 */

	public List<IndexSpecification> getIndexSpecifications()
	{
		return m_indexes;
	}
}
