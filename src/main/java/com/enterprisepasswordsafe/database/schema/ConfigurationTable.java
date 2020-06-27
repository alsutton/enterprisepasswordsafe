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

import com.enterprisepasswordsafe.database.ConfigurationDAO;
import com.enterprisepasswordsafe.database.ConfigurationOption;

import java.sql.SQLException;

public final class ConfigurationTable
	extends AbstractTable{

	/**
	 * The name of this table
	 */

	private static final String TABLE_NAME = "configuration";

	/**
	 * Column information
	 */

	private static final ColumnSpecification NAME_COLUMN = new ColumnSpecification("property_name", ColumnSpecification.TYPE_SHORT_STRING, true, true);
	private static final ColumnSpecification VALUE_COLUMN = new ColumnSpecification("property_value", ColumnSpecification.TYPE_LONG_STRING);

    private static final ColumnSpecification[] COLUMNS = {
    	NAME_COLUMN, VALUE_COLUMN
    };

    /**
     * Index information
     */

    private static final IndexSpecification NAME_INDEX = new IndexSpecification("cf_pnme", TABLE_NAME, NAME_COLUMN);

    private static final IndexSpecification[] INDEXES = {
    	NAME_INDEX
    };

	/**
	 * The property names which need changing
	 */

	private static final String[] OLD_PROPERTY_NAMES = {
		"smtp.host",
		"smtp.from",
		"smtp.to"
	};

	/**
	 * The new names for the properties
	 */

	private static final String[] NEW_PROPERTY_NAMES = {
		"smtphost",
		"smtpfrom",
		"smtpto"
	};

	/**
	 * The list of property names to set for the SMTP migration
	 */

	private static final String[] SMTP_PROPERTY_NAMES = {
		"smtp.enabled.authentication",
		"smtp.enabled.configuration",
		"smtp.enabled.reports",
        "smtp.enabled.user_manipulation",
        "smtp.enabled.group_manipulation",
        "smtp.enabled.object_manipulation",
        "smtp.enabled.hierarchy_manipulation",
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
		if(schemaID >= SchemaVersion.CURRENT_SCHEMA)
			return;

		if(schemaID < SchemaVersion.SCHEMA_201112) {
	    	ConfigurationDAO cDAO = ConfigurationDAO.getInstance();
	    	for(int i = 0 ; i < OLD_PROPERTY_NAMES.length ; i++) {
	    		String value = cDAO.get(OLD_PROPERTY_NAMES[i], null);
	    		if( value != null ) {
	    			cDAO.set(NEW_PROPERTY_NAMES[i], value);
	    			cDAO.delete(OLD_PROPERTY_NAMES[i]);
	    		}
	    	}

			String smtpSetting = ConfigurationDAO.getValue(ConfigurationOption.SMTP_ENABLED);
	    	if( smtpSetting != null ) {
				for(String property : SMTP_PROPERTY_NAMES) {
					cDAO.set(property, smtpSetting);
				}
				cDAO.delete(ConfigurationOption.SMTP_ENABLED);
	    	}
		}
	}

	/**
	 * Gets an instance of this table schema
	 */

	protected static ConfigurationTable getInstance() {
		return new ConfigurationTable();
	}
}
