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

import com.enterprisepasswordsafe.engine.utils.InvalidLicenceException;
import com.enterprisepasswordsafe.engine.utils.KeyUtils;
import com.enterprisepasswordsafe.proguard.ExternalInterface;

import javax.crypto.SecretKey;
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

public final class MembershipDAO
		extends JDBCBase
		implements ExternalInterface {

    private static final Object MEMBERSHIP_MARKER = new Object();

    public static final String MEMBERSHIP_FIELDS = " mem.user_id, mem.group_id, mem.akey ";

    private static final String GET_MEMBERSHIP_SQL =
            "SELECT " + MEMBERSHIP_FIELDS + "  FROM membership mem  WHERE mem.user_id = ? AND mem.group_id = ? ";

    private static final String GET_MEMBERSHIPS_FOR_USER_SQL =
            "SELECT " + MEMBERSHIP_FIELDS + "  FROM membership mem WHERE mem.user_id = ? ";

    private static final String WRITE_MEMBERSHIP_SQL =
    		"INSERT INTO membership(user_id, group_id, akey) VALUES (?,?,?)";

    private static final String UPDATE_MEMBERSHIP_KEY_SQL =
    		"UPDATE membership SET akey = ? WHERE user_id = ? AND group_id = ?";

    private static final String DELETE_MEMBERSHIP_SQL =
    		"DELETE FROM membership WHERE user_id = ? AND group_id = ? ";

    private static final String GET_USER_MEMBERSHIPS_SQL =
            "SELECT   grp.group_id "
                    + "  FROM groups grp, application_users u, membership m "
                    + " WHERE u.user_id = ? AND (u.disabled is null or u.disabled = 'N')"
                    + "   AND m.user_id = u.user_id AND m.group_id = grp.group_id "
                    + "   AND grp.group_id != '0' AND grp.group_id != '1' "
                    + "   AND grp.group_id != '2' AND grp.group_id != '3' ";

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
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(WRITE_MEMBERSHIP_SQL)) {
            ps.setString(1, membership.getUserId());
            ps.setString(2, membership.getGroupId());
            SecretKey accessKey = membership.getAccessKey();
            if(accessKey == null) {
                ps.setNull(3, Types.BLOB);
            } else {
                ps.setBytes(3, KeyUtils.encryptKey(membership.getAccessKey(), user.getKeyEncrypter()));
            }
            ps.executeUpdate();
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
        Group theGroup = UnfilteredGroupDAO.getInstance().getById(groupId);

        Membership membership = getMembership(remoteUser, theGroup);
        if(membership == null) {
            // Go via the admin user if there is no direct membership.
            User adminUser = UserDAO.getInstance().getAdminUserForUser(remoteUser);
            membership = getMembership(adminUser, theGroup);
        }
        theGroup.updateAccessKey(membership);

        create(user, theGroup);
        TamperproofEventLogDAO.getInstance().create( TamperproofEventLog.LOG_LEVEL_USER_MANIPULATION,
			remoteUser, null,"Added {user:" + remoteUser.getId()
				+ "} to the group {group:" + theGroup.getGroupId() + "}",true);

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

	    try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_MEMBERSHIP_SQL)) {
	        ps.setString(1, user.getId());
	        ps.setString(2, groupId);
	        try(ResultSet rs = ps.executeQuery()) {
		        return rs.next() ? new Membership(rs, 1, user) : null;
	        }
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

	    return exists(GET_MEMBERSHIP_SQL, userId, groupId);
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
        delete(user.getId(), group.getGroupId());
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
        delete(user.getId(), groupId);
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
    	runResultlessParameterisedSQL(DELETE_MEMBERSHIP_SQL, userId, groupId);
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
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_MEMBERSHIPS_FOR_USER_SQL)) {
            ps.setString(1, user.getId());
            try(ResultSet rs = ps.executeQuery()) {
	            while(rs.next()) {
		            final Membership membership = new Membership( rs, 1, user);
		            memberships.add(membership);
	            }
            }
        }

        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(UPDATE_MEMBERSHIP_KEY_SQL)) {
            for( Membership membership : memberships ) {
            	ps.setBytes(1, KeyUtils.encryptKey(membership.getAccessKey(), encrypter));
            	ps.setString(2, membership.getUserId());
            	ps.setString(3, membership.getGroupId());
            	ps.addBatch();
            }
            ps.executeBatch();
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
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_USER_MEMBERSHIPS_SQL)) {
            ps.setString(1, id);
            try(ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    membershipMap.put(rs.getString(1), MEMBERSHIP_MARKER);
                }
            }
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
