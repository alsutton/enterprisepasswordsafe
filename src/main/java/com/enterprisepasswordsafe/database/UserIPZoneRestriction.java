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

import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Representation of a restriction for a user when they are trying to log in from a given zone.
 */
public class UserIPZoneRestriction {

    /**
     * The character to represent an "allow" rule. 
     */

    public static final String ALLOW_STRING = "Y";
    
    /**
     * The integer to represent an "allow" rule. 
     */

    public static final int ALLOW_INT = 1;
    
    /**
     * The character to represent an "deny" rule. 
     */

    public static final String DENY_STRING = "N";
    
    /**
     * The integer to represent an "dent" rule. 
     */

    public static final int DENY_INT = 2;
    
    /**
     * The character to represent a non existant rule 
     */

    public static final String DEFAULT_STRING = "D";

    /**
     * The ID of this network zone
     */

    private String zoneId;

    /**
     * The ID of the user.
     */

    private String userId;

    /**
     * The rule.
     */
    private int rule;

    /**
     * Constructor. Create a new Restruction.
     * 
     * @param theZoneId The ID of the zone for this restriction.
     * @param theUserId The ID of the user for this restriction.
     * @param theRule The restruction rule.
     */
    
    public UserIPZoneRestriction( final String theZoneId, 
            final String theUserId, final int theRule ) {
        zoneId = theZoneId;
        userId = theUserId;
        rule = theRule;
    }
    
    /**
     * Constructor. Extract the data from the ResultSet.
     * 
     * @param rs The ResultSet to extract the restruction from.
     */
    
    public UserIPZoneRestriction( ResultSet rs ) 
        throws SQLException {
        int idx = 1;
        zoneId = rs.getString(idx++);
        userId = rs.getString(idx++);
        rule = rs.getInt(idx);
    }
    
    /**
     * @return Returns the rule.
     */
    public final int getRule() {
        return rule;
    }

    /**
     * Set the rule value.
     * 
     * @param newRule The rule to set.
     */
    public final void setRule(int newRule) {
        rule = newRule;
    }

	public String getZoneId() {
		return zoneId;
	}

	public void setZoneId(String zoneId) {
		this.zoneId = zoneId;
	}

	public String getUserId() {
		return userId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}
}
