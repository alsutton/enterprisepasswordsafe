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


/**
 * Class handling the specification for a column in a database.
 */

public final class ColumnSpecification
{
	/**
	 * The types for the columns
	 */

	public static final Integer	TYPE_INT = Integer.valueOf( 1 ),
								TYPE_LONG = Integer.valueOf( 2 ),
								TYPE_CHAR = Integer.valueOf( 3 ),
								TYPE_SHORT_STRING = Integer.valueOf( 4 ),
								TYPE_LONG_STRING = Integer.valueOf( 5 ),
								TYPE_ID = Integer.valueOf(6),
								TYPE_BLOB = Integer.valueOf(7),
								TYPE_MULTI_BLOB = Integer.valueOf(8),
								TYPE_IP_ADDRESS = Integer.valueOf(9),
								TYPE_KEY = Integer.valueOf(10);

	/**
	 * The name of the table.
	 */

	private final String name;

	/**
	 * The type.
	 */

	private final Integer type;

	/**
	 * Whether or not this column should only contain unique values.
	 */

	private final boolean uniqueOnly;

	/**
	 * Whether or not this column should allow null values
	 */

	private final boolean rejectNulls;

	/**
	 * Constructor.
	 *
	 * @param name The name of the table.
	 * @param type The column type/
	 */

	public ColumnSpecification( final String name, final Integer type )
	{
		this( name, type, false, false );
	}

	/**
	 * Constructor.
	 *
	 * @param name The name of the table.
	 * @param type The column type/
	 * @param uniqueOnly Whether or not this column should contain unique values on each row.
	 * @param rejectNulls Whether or not this column can contain null values.
	 */

	public ColumnSpecification( String name, Integer type, boolean uniqueOnly, boolean rejectNulls )
	{
		this.name = name;
		this.type = type;
		this.uniqueOnly = uniqueOnly;
		this.rejectNulls = rejectNulls;
	}

	/**
	 * Get the name of the column,
	 *
	 * @return The name of the column.
	 */

	public String getName()
	{
		return name;
	}

	/**
	 * Get the type of the column,
	 *
	 * @return The type of the column.
	 */

	public Integer getType()
	{
		return type;
	}

	/**
	 * Get whether or not this column should contain only unique values.
	 *
	 * @return true if only unique values should be allowed, false if not.
	 */

	public boolean getUniqueOnly()
	{
		return uniqueOnly;
	}

	/**
	 * Get whether or not this column should allow null values.
	 *
	 * @return true if nulls should not be allowed, false if nulls should be allowed..
	 */

	public boolean getRejectNulls()
	{
		return rejectNulls;
	}
}
