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

package com.enterprisepasswordsafe.database;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class ConfigurationDAO
        extends JDBCBase {

    private static final String GET_SQL =
            "SELECT property_value FROM configuration WHERE property_name = ?";

    private static final String UPDATE_SQL =
            "UPDATE configuration SET property_value = ? WHERE property_name = ?";

    private static final String INSERT_SQL =
            "INSERT INTO configuration(property_value, property_name) VALUES (?, ?)";

    private static final String DELETE_SQL =
            "DELETE FROM configuration WHERE property_name = ?";

	private static final Map<String,CachedValue> cache = new HashMap<>();

	private ConfigurationDAO() {
		super();
	}

    public String get(final ConfigurationOption configurationOption)
        throws SQLException {
        if (configurationOption == null) {
            return null;
        }

        return get(configurationOption.getPropertyName(), configurationOption.getDefaultValue());
    }

    public String get(final String name, final String defaultValue)
            throws SQLException {
        if (name == null) {
            return null;
        }

        String cachedValue = getValueFromCache(name);
        if(cachedValue != null) {
            return cachedValue;
        }

        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_SQL)) {
            ps.setString(1, name);
            ps.setMaxRows(1);

            try(ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return defaultValue;
                }

                String value = rs.getString(1);
                if(rs.wasNull()) {
                    return defaultValue;
                }

                synchronized(cache) {
                    cache.put(name, new CachedValue(value));
                }

                return value;
            }
        }
    }

    private boolean exists(final String name)
            throws SQLException {
        if (name == null) {
            return false;
        }
        return exists(GET_SQL, name);
    }

    public void delete(final ConfigurationOption configurationOption)
        throws SQLException {
        if (configurationOption == null) {
            return;
        }

        delete(configurationOption.getPropertyName());
    }

    public void delete(final String name)
            throws SQLException {
        if (name == null) {
            return;
        }

        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_SQL)) {
            ps.setString(1, name);
            ps.executeUpdate();
        }

        synchronized (cache) {
            cache.remove(name);
        }
    }

    public void set(final ConfigurationOption configurationOption, final String value)
            throws SQLException {
        set(configurationOption.getPropertyName(), value);
    }

    public void set(final String name, final String value)
        throws SQLException {
        String sqlStatement = exists(name) ? UPDATE_SQL : INSERT_SQL;

        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sqlStatement)) {
            ps.setString(1, value);
            ps.setString(2, name);
            ps.executeUpdate();
        }

        putValueInCache(name, value);

        final List<ConfigurationListenersDAO.ConfigurationListener> listeners =
        	ConfigurationListenersDAO.getListenersForProperty(name);
        if( listeners != null )
        {
        	for(ConfigurationListenersDAO.ConfigurationListener thisListener: listeners) {
	        	thisListener.configurationChange(name, value);
	        }
        }
    }

    private void putValueInCache(final String name, final String value) {
        synchronized(cache) {
            if (value == null) {
                cache.remove(name);
                return;
            }
            cache.put(name, new CachedValue(value));
        }
    }

    private String getValueFromCache(final String name) {
        synchronized(cache) {
            CachedValue cachedValue = cache.get(name);
            if( cachedValue != null ) {
                if( cachedValue.hasExpired() ) {
                    cache.remove(name);
                } else {
                    return cachedValue.getValue();
                }
            }
        }

        return null;
    }



    /**
     * Class holding a cached configuration value.
     */

    private static class CachedValue {
    	/**
    	 * The maximum life of a cached entry.
    	 */

    	private static final long CACHE_LIFETIME = 30 * 1000;	// 30s

    	/**
    	 * The time the record was inserted into the cache.
    	 */

    	private final long insertTime;

    	/**
    	 * The value.
    	 */

    	private final String value;

    	/**
    	 * Constructor. Stores data.
    	 *
    	 * @param newValue The value to be cached.
    	 */
    	private CachedValue( String newValue ) {
    		insertTime = System.currentTimeMillis();
    		value = newValue;
    	}

    	/**
    	 * Check to see if this entry has expired.
    	 */

    	boolean hasExpired() {
    		return System.currentTimeMillis() > (insertTime + CACHE_LIFETIME);
    	}

    	/**
    	 * Gets the value.
    	 */

    	String getValue() {
    		return value;
    	}
    }

    public static String getValue(final ConfigurationOption configurationOption)
            throws SQLException {
    	return getInstance().get(configurationOption);
    }

    public static String getValue(final String propertyName, final String defaultValue)
            throws SQLException {
        return getInstance().get(propertyName, defaultValue);
    }

    public static Long getLongValue(final ConfigurationOption configurationOption) {
        try {
            String value = getValue(configurationOption);
            return parseLongValue(value);
        } catch(SQLException | NumberFormatException e) {
            try {
                return parseLongValue(configurationOption.getDefaultValue());
            } catch (NumberFormatException nfe) {
                return null;
            }
        }
    }

    private static Long parseLongValue(String value)
        throws NumberFormatException {
        if(value == null) {
            return null;
        }

        return Long.parseLong(value);
    }

    //------------------------

    private static final class InstanceHolder {
    	static final ConfigurationDAO INSTANCE = new ConfigurationDAO();
    }

    public static ConfigurationDAO getInstance() {
    	return InstanceHolder.INSTANCE;
   }
}
