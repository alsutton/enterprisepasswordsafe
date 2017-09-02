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

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.enterprisepasswordsafe.engine.utils.Cache;
import com.enterprisepasswordsafe.engine.utils.DatabaseConnectionUtils;
import com.enterprisepasswordsafe.engine.utils.InvalidLicenceException;
import com.enterprisepasswordsafe.engine.utils.KeyUtils;
import com.enterprisepasswordsafe.proguard.ExternalInterface;

import javax.crypto.SecretKey;


/**
 * Data access object for the user access control.
 *
 * @author alsutton
 */

public final class MembershipDAO implements ExternalInterface {
    /**
     * The marker used in a membership map to show a user belongs to a group
     */

    private static final Object MEMBERSHIP_MARKER = new Object();

    /**
     * The SQL Fields needed to construct a membership object.
     */

    public static final String MEMBERSHIP_FIELDS = " mem.user_id, mem.group_id, mem.akey ";

    /**
     * The SQL to get a specific membership object.
     */

    private static final String GET_MEMBERSHIP_SQL = "SELECT "
            + MEMBERSHIP_FIELDS + "  FROM membership mem "
            + " WHERE mem.user_id = ? " + "   AND mem.group_id = ? ";

    /**
     * The SQL to get a specific membership object.
     */

    private static final String GET_MEMBERSHIPS_FOR_USER_SQL = "SELECT "
            + MEMBERSHIP_FIELDS + "  FROM membership mem "
            + " WHERE mem.user_id = ? ";

    /**
     * The SQL statement to write the details of a membership.
     */

    private static final String WRITE_MEMBERSHIP_SQL =
    		"INSERT INTO membership(user_id, group_id, akey) VALUES (?,?,?)";

    /**
     * The SQL statement to update a membership key
     */

    private static final String UPDATE_MEMBERSHIP_KEY_SQL =
    		"UPDATE membership SET akey = ? WHERE user_id = ? AND group_id = ?";

    /**
     * The SQL to delete a specific membership object.
     */

    private static final String DELETE_MEMBERSHIP_SQL =
    		"DELETE FROM membership WHERE user_id = ? AND group_id = ? ";

    /**
     * The SQL statement to get the groups a user has access to.
     */

    private static final String GET_USER_MEMBERSHIPS_SQL =
            "SELECT   grp.group_id "
                    + "  FROM groups grp, "
                    + "       application_users u, "
                    + "       membership m "
                    + " WHERE u.user_id = ? "
                    + "   AND (u.disabled is null or u.disabled = 'N')"
                    + "   AND m.user_id = u.user_id "
                    + "   AND m.group_id = grp.group_id "
                    + "   AND grp.group_id != '0' "
                    + "   AND grp.group_id != '1' "
                    + "   AND grp.group_id != '2' "
                    + "   AND grp.group_id != '3' ";

    /**
	 * A cache of memberships previously fetched.
	 */

	private static Cache<String, Membership> cache = new Cache<String, Membership>();

	/**
	 * Private constructor to prevent instantiation
	 */

	private MembershipDAO() {
		super();
	}

	/**
	 * Generates the cache key from a membership
	 */

	private String generateCacheKey(final Membership membership) {
		return generateCacheKey(membership.getUserId(), membership.getGroupId());
	}

	private String generateCacheKey(final String userId, final String groupId) {
		return "mem_"+userId+"_"+groupId;
	}

    /**
     * Writes a group membership to the database.
     *
     * @param user The user involved in the membership.
     * @param membership The membership to store.
     *
     * @throws SQLException If there was a problem writing to the database.
     * @throws GeneralSecurityException Thrown if there was a decryption problem.
     * @throws UnsupportedEncodingException
     * @throws InvalidLicenceException Thrown if there EPS licence is not valid.
     */

    public void write(final User user, Membership membership)
        throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(WRITE_MEMBERSHIP_SQL);
        try {
            int idx = 1;
            ps.setString(idx++, membership.getUserId());
            ps.setString(idx++, membership.getGroupId());
            SecretKey accessKey = membership.getAccessKey();
            if(accessKey == null) {
                ps.setNull(idx, Types.BLOB);
            } else {
                ps.setBytes(idx, KeyUtils.encryptKey(membership.getAccessKey(), user.getKeyEncrypter()));
            }
            ps.executeUpdate();

    		cache.put(generateCacheKey(membership), membership);
        } finally {
        	DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Creates a new membership for a user to a group
     *
     * @param user The user who is joining the group.
     * @param group The group they are joining.
     *
     * @throws SQLException If there was a problem writing to the database.
     * @throws GeneralSecurityException Thrown if there was a decryption problem.
     * @throws UnsupportedEncodingException
     */

    public Membership create(final User user, final Group group)
    	throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
        Membership membership = getMembership(user, group);
        if( membership == null) {
            membership = new Membership(user, group);
            write(user, membership);
        }
        return membership;
    }

    /**
     * Creates a new membership for a user to a group
     *
     * @param user The user who is joining the group.
     * @param groupId The group they are joining.
     *
     * @throws SQLException If there was a problem writing to the database.
     * @throws GeneralSecurityException Thrown if there was a decryption problem.
     * @throws UnsupportedEncodingException
     */

    public Membership create(final User user, final String groupId)
            throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
        return create(user, GroupDAO.getInstance().getById(groupId));
    }

    /**
     * Creates a new membership for a user to a group
     *
     * @param remoteUser The user adding the specified user to the group.
     * @param user The user who is joining the group.
     * @param groupId The group they are joining.
     *
     * @throws SQLException If there was a problem writing to the database.
     * @throws GeneralSecurityException Thrown if there was a decryption problem.
     * @throws UnsupportedEncodingException
     */

    public Membership create(final User remoteUser, final User user, final String groupId)
            throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
        Group theGroup = GroupDAO.getInstance().getByIdEvenIfDisabled(groupId);

        Membership membership = getMembership(remoteUser, theGroup);
        if(membership == null) {
            // Go via the admin user if there is no direct membership.
            User adminUser = UserDAO.getInstance().getAdminUserForUser(remoteUser);
            membership = getMembership(adminUser, theGroup);
        }
        theGroup.updateAccessKey(membership);

        create(user, theGroup);
        TamperproofEventLogDAO.getInstance().create(
                TamperproofEventLog.LOG_LEVEL_USER_MANIPULATION,
                remoteUser,
                null,
                "Added {user:" + remoteUser.getUserId()
                        + "} to the group {group:" + theGroup.getGroupId() + "}",
                true);

        return create(user, GroupDAO.getInstance().getById(groupId));
    }

    /**
	 * Get a users membership of a group.
	 *
	 * @param user The user to get the membership for.
	 * @param group The group to get the membership of.
	 *
	 * @return A membership objectm or null if it does not exist.
	 *
	 * @throws SQLException Thrown if there is a problem accessing the database.
	 * @throws GeneralSecurityException Thrown if there is a problem decrypting.
	 * @throws UnsupportedEncodingException
	 */

	public Membership getMembership(final User user, final Group group)
	    throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
		return getMembership(user, group.getGroupId());
	}

	/**
	 * Get a users membership of a group.
	 *
	 * @param user The user to get the membership for.
	 * @param groupId The group ID to get the membership of.
	 *
	 * @return A membership objectm or null if it does not exist.
	 *
	 * @throws SQLException Thrown if there is a problem accessing the database.
	 * @throws GeneralSecurityException Thrown if there is a problem decrypting.
	 * @throws UnsupportedEncodingException
	 */

	public Membership getMembership(final User user, final String groupId)
	    throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
	    if (user == null || groupId == null) {
	        return null;
	    }

	    final String cacheKey = generateCacheKey(user.getUserId(), groupId);
    	Membership membership = cache.get(cacheKey);
    	if(membership != null) {
    		return membership;
    	}

	    PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_MEMBERSHIP_SQL);
	    try {
	        ps.setString(1, user.getUserId());
	        ps.setString(2, groupId);

	        ResultSet rs = ps.executeQuery();
	        try {
		        if (!rs.next()) {
		        	return null;
		        }

	            membership = new Membership(rs, 1, user);
	            cache.put(cacheKey, membership);
	            return membership;
	        } finally {
		        DatabaseConnectionUtils.close(rs);
	        }
	    } finally {
	    	DatabaseConnectionUtils.close(ps);
	    }
	}

	/**
	 * Get a users membership of a group.
	 *
	 * @param userId The ID of the user to get the membership for.
	 * @param groupId The group ID to get the membership of.
	 *
	 * @return A membership objectm or null if it does not exist.
	 *
	 * @throws SQLException Thrown if there is a problem accessing the database.
	 */

	public boolean isMemberOf(final String userId, final String groupId)
	    throws SQLException {
	    if (userId == null || groupId == null) {
	        return false;
	    }

	    if (cache.get(generateCacheKey(userId, groupId)) != null) {
	    	return true;
	    }

	    PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_MEMBERSHIP_SQL);
	    try {
	        ps.setString(1, userId);
	        ps.setString(2, groupId);

	        ResultSet rs = ps.executeQuery();
	        try {
	        	return rs.next();
	        } finally {
		        DatabaseConnectionUtils.close(rs);
	        }
	    } finally {
	        DatabaseConnectionUtils.close(ps);
	    }
	}

	/**
	 * Remove a user from a group
	 *
     * @param user The user to delete the membership for.
	 * @param group The group to delete the membership for.
	 *
	 * @throws SQLException Thrown if there is a problem accessing the database.
	 * @throws GeneralSecurityException Thrown if there is a problem decrypting.
	 * @throws UnsupportedEncodingException
	 */

	public void delete(final User user, final Group group)
	    throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        delete(user.getUserId(), group.getGroupId());
	}

    /**
     * Remove a user from a group
     *
     * @param userId The ID of the user to delete the membership for.
     * @param group The group to delete the membership for.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting.
     * @throws UnsupportedEncodingException
     */

    public void delete(final String userId, final Group group)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        delete(userId, group.getGroupId());
    }

    /**
     * Remove a user from a group
     *
     * @param user The user to delete the membership for.
     * @param groupId The ID of the group to delete the membership for.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting.
     * @throws UnsupportedEncodingException
     */

    public void delete(final User user, final String groupId)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        delete(user.getUserId(), groupId);
    }

    /**
     * Remove a user from a group
     *
     * @param userId The ID of the user to delete the membership for.
     * @param groupId The ID of the group to delete the membership for.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting.
     * @throws UnsupportedEncodingException
     */

    public void delete(final String userId, final String groupId)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        cache.remove(generateCacheKey(userId, groupId));

        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_MEMBERSHIP_SQL);
        try {
            ps.setString(1, userId);
            ps.setString(2, groupId);
            ps.executeUpdate();
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Update the encryption on the memberships of a user.
     *
     * @param user The user to update the memberships for.
     * @param encrypter The encrypter to use to update the memberships.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     *
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException
     */

    public void updateEncryptionOnKeys(final User user, final Encrypter encrypter)
        throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
        if (user == null) {
            return;
        }

        List<Membership> memberships = new ArrayList<Membership>();
        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_MEMBERSHIPS_FOR_USER_SQL);
        try {
            ps.setString(1, user.getUserId());
            ResultSet rs = ps.executeQuery();
            try {
	            while(rs.next()) {
		            final Membership membership = new Membership( rs, 1, user);
		            memberships.add(membership);
	            }
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
        	DatabaseConnectionUtils.close(ps);
        }

        ps = BOMFactory.getCurrentConntection().prepareStatement(UPDATE_MEMBERSHIP_KEY_SQL);
        try {
            for( Membership membership : memberships ) {
            	int idx = 1;
            	ps.setBytes(idx++, KeyUtils.encryptKey(membership.getAccessKey(), encrypter));
            	ps.setString(idx++, membership.getUserId());
            	ps.setString(idx, membership.getGroupId());
            	ps.addBatch();
            }
            ps.executeBatch();
        } finally {
        	DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Adds entries to a Map for all the groups a user belongs to.
     *
     * @param id The id of the user to get the memberships for.
     *
     * @return A map of Group IDs to MEMBERSHIP_MARKER which is has entries for the groups a user is a member of.
     *
     * @throws SQLException
     *             Thrown if there is a problem accessing the database.
     */

    public Map<String,Object> getMemberships(final String id) throws SQLException {
        Map<String, Object> membershipMap = new HashMap<String,Object>();

        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_USER_MEMBERSHIPS_SQL);
        try {
            ps.setString(1, id);
            ResultSet rs = ps.executeQuery();
            try {
                while (rs.next()) {
                    membershipMap.put(rs.getString(1), MEMBERSHIP_MARKER);
                }
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
            DatabaseConnectionUtils.close(ps);
        }

        return membershipMap;
    }

    //------------------------

    private static class InstanceHolder {
    	final static MembershipDAO INSTANCE = new MembershipDAO();
    }

    public static MembershipDAO getInstance() {
    	return InstanceHolder.INSTANCE;
    }
}
