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

import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class UserIPZoneRestrictionDAO {

    private static final String GET_BY_USER_ID_AND_IP_SQL =
        "SELECT uipz.ip_zone_id, uipz.user_id, uipz.setting FROM user_ip_zones uipz,  ip_zones ipz "
        + " WHERE ipz.ip_version = ? AND ipz.ip_start <= ? AND ipz.ip_end   >= ? "
        + "   AND ipz.ip_zone_id = uipz.ip_zone_id AND uipz.user_id = ?";


    private static final String GET_BY_ZONE_AND_USER_SQL =
        "SELECT ip_zone_id, user_id, setting FROM user_ip_zones WHERE ip_zone_id = ? AND user_id = ?";

    private static final String GET_BY_USER_ID_SQL =
        "SELECT ip_zone_id, setting  FROM user_ip_zones WHERE user_id = ?";

    private static final String STORE_SQL =
        "INSERT INTO user_ip_zones(ip_zone_id, user_id, setting) VALUES( ?, ?, ? )";

    private static final String UPDATE_SQL =
        "UPDATE user_ip_zones SET setting = ? WHERE ip_zone_id = ? AND user_id    = ?";

    private static final String DELETE_SQL =
        "DELETE FROM user_ip_zones WHERE ip_zone_id = ? AND user_id = ?";

	private UserIPZoneRestrictionDAO() {
		super();
	}

    public final UserIPZoneRestriction create( final String zoneId, final String userId, final int rule )
    	throws SQLException {
    	UserIPZoneRestriction ipzr = new UserIPZoneRestriction(zoneId, userId, rule);
    	store(ipzr);
    	return ipzr;
    }

    public final List<UserIPZoneRestriction> getApplicable( final String id, final String ip )
        throws SQLException, UnknownHostException, GeneralSecurityException {

    	int ipVersion;
    	String dbString;
    	if( ip.indexOf('.') == -1 && ip.indexOf(':') != -1 ) {
    		ipVersion = 6;
    		dbString = IPZone.convertIP6ToDBString(ip);
    	} else {
    		ipVersion = 4;
    		dbString = IPZone.convertIP4ToDBString(ip);
    	}

        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_BY_USER_ID_AND_IP_SQL)) {
            ps.setInt    (1, ipVersion);
            ps.setString (2, dbString);
            ps.setString (3, dbString);
            ps.setString (4, id);
            try(ResultSet rs = ps.executeQuery()) {
	            List<UserIPZoneRestriction> results = new ArrayList<UserIPZoneRestriction>();
	            while(rs.next()) {
	                results.add(new UserIPZoneRestriction(rs));
	            }

	            return results;
            }
        }
    }

    public void store( final UserIPZoneRestriction ipzr )
        throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(STORE_SQL)) {
            ps.setString(1, ipzr.getZoneId());
            ps.setString(2, ipzr.getUserId());
            ps.setInt   (3, ipzr.getRule());
            ps.executeUpdate();
        }
    }

    public void update( final UserIPZoneRestriction ipzr )
        throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(UPDATE_SQL)) {
            ps.setInt   (1, ipzr.getRule());
            ps.setString(2, ipzr.getZoneId());
            ps.setString(3, ipzr.getUserId());
            ps.executeUpdate();
        }
    }

    public void delete( final UserIPZoneRestriction ipzr )
        throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_SQL)) {
            ps.setString(1, ipzr.getZoneId());
            ps.setString(2, ipzr.getUserId());
            ps.executeUpdate();
        }
    }

    public final UserIPZoneRestriction getByZoneAndUser( final String userId, final String zoneId )
        throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_BY_ZONE_AND_USER_SQL)) {
            ps.setString(1, zoneId);
            ps.setString(2,   userId);
            try(ResultSet rs = ps.executeQuery()) {
	            return rs.next() ? new UserIPZoneRestriction(rs) : null;
            }
        }
    }

    public final Map<String,String> getRulesForUser( final String id ) throws SQLException {
        Map<String,String> rules = new HashMap<String,String>();
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_BY_USER_ID_SQL)) {
            ps.setString(1, id);
            try(ResultSet rs = ps.executeQuery()) {
	            while( rs.next() ) {
	                String zoneId = rs.getString(1);
	                int rule = rs.getInt(2);
	                if(!rs.wasNull()) {
	                    if          (rule == UserIPZoneRestriction.ALLOW_INT) {
	                        rules.put(zoneId, UserIPZoneRestriction.ALLOW_STRING);
	                    } else if   (rule == UserIPZoneRestriction.DENY_INT ) {
	                        rules.put(zoneId, UserIPZoneRestriction.DENY_STRING);
	                    }
	                }
	            }
            }
        }

        return rules;
    }

    //------------------------

    private static final class InstanceHolder {
    	static final UserIPZoneRestrictionDAO INSTANCE = new UserIPZoneRestrictionDAO();
    }

    public static UserIPZoneRestrictionDAO getInstance() {
		return InstanceHolder.INSTANCE;
    }
}
