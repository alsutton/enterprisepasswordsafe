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

package com.enterprisepasswordsafe.engine.database;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.enterprisepasswordsafe.engine.utils.DatabaseConnectionUtils;
import com.enterprisepasswordsafe.engine.utils.IDGenerator;
import com.enterprisepasswordsafe.proguard.ExternalInterface;

/**
 * DAO for accessing information about password locations
 */

public class LocationDAO
	implements ExternalInterface {

	/**
	 * The SQL to find the id of a location by its name.
	 */

	private static final String GET_BY_NAME_SQL = "select id from locations where name = ?";

	/**
	 * The SQL to find all the location names in use
	 */

	private static final String GET_ALL_SQL = "select id, name from locations ORDER BY name";

    /**
     * The SQL to write a new password into the database.
     */

    private static final String WRITE_LOCATION_SQL = "INSERT INTO locations (id, name) VALUES (?, ?)";

    /**
	 * Get all of the known systems passwords have been stored for.
	 *
     * @return a List of all the known password systems.
	 */

	public List<LocationDetails> getAll()
		throws SQLException {
        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_ALL_SQL);
        try {
        	ResultSet rs = ps.executeQuery();
        	try {
        		List<LocationDetails> results = new ArrayList<LocationDetails>();
        		while(rs.next()) {
        			results.add(new LocationDetails(rs.getString(1), rs.getString(2)));
        		}
        		return results;
        	} finally {
        		DatabaseConnectionUtils.close(rs);
        	}
        } finally {
        	DatabaseConnectionUtils.close(ps);
        }
	}

    /**
	 * Gets the ID for a specific location
	 *
	 * @param location The location to get the ID for
	 *
	 * @return The
	 *
	 */

	private String getIdByName(final String location)
		throws SQLException {
        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_BY_NAME_SQL);
        try {
        	ps.setString(1, location);
        	ResultSet rs = ps.executeQuery();
        	try {
        		if(!rs.next()) {
        			return null;
        		}
        		return rs.getString(1);
        	} finally {
        		DatabaseConnectionUtils.close(rs);
        	}
        } finally {
        	DatabaseConnectionUtils.close(ps);
        }
	}

	/**
	 * Adds a location and returns the ID
	 */

	private String addLocation(final String name)
		throws SQLException {
		String id = IDGenerator.getID();

        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(WRITE_LOCATION_SQL);
        try {
        	ps.setString(1, id);
        	ps.setString(2, name);
        	ps.executeUpdate();

        	return id;
        } finally {
        	DatabaseConnectionUtils.close(ps);
        }
	}

	/**
	 * Gets an ID for a location, if the location doesn't exist a new location
	 * is added and that ID returned.
	 */

	public String getId(final String location)
		throws SQLException {
		String existingId = getIdByName(location);
		if(existingId != null) {
			return existingId;
		}

		return addLocation(location);
	}

    private static final class InstanceHolder {
        private static final LocationDAO INSTANCE = new LocationDAO();
    }

    public static LocationDAO getInstance() {
		return InstanceHolder.INSTANCE;
    }

    /**
     * The details of a location
     */

    public static class LocationDetails {
    	private final String id;
    	private final String name;

    	LocationDetails(final String id, final String name) {
    		this.id = id;
    		this.name = name;
    	}

		public String getId() {
			return id;
		}

		public String getName() {
			return name;
		}
    }
}
