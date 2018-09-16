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

import com.enterprisepasswordsafe.engine.utils.IDGenerator;
import com.enterprisepasswordsafe.proguard.ExternalInterface;

import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class LocationDAO
	implements ExternalInterface {

	private static final String GET_BY_NAME_SQL = "select id from locations where name = ?";

	private static final String GET_ALL_SQL = "select id, name from locations ORDER BY name";

    private static final String WRITE_LOCATION_SQL = "INSERT INTO locations (id, name) VALUES (?, ?)";

	public List<LocationDetails> getAll()
		throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_ALL_SQL)) {
        	try(ResultSet rs = ps.executeQuery()) {
        		List<LocationDetails> results = new ArrayList<LocationDetails>();
        		while(rs.next()) {
        			results.add(new LocationDetails(rs.getString(1), rs.getString(2)));
        		}
        		return results;
        	}
        }
	}

	private String getIdByName(final String location)
		throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_BY_NAME_SQL)) {
        	ps.setString(1, location);
        	try(ResultSet rs = ps.executeQuery()) {
        		return rs.next() ? rs.getString(1) : null;
        	}
        }
	}

	private String addLocation(final String name)
		throws SQLException {
		String id = IDGenerator.getID();
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(WRITE_LOCATION_SQL)) {
        	ps.setString(1, id);
        	ps.setString(2, name);
        	ps.executeUpdate();
        	return id;
        }
	}

	public String getId(final String location)
		throws SQLException {
		String existingId = getIdByName(location);
		return existingId != null ? existingId : addLocation(location);
	}

    private static final class InstanceHolder {
        private static final LocationDAO INSTANCE = new LocationDAO();
    }

    public static LocationDAO getInstance() {
		return InstanceHolder.INSTANCE;
    }

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
