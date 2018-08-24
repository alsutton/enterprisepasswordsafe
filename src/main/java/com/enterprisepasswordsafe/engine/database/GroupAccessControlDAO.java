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
import java.security.PrivateKey;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Set;
import java.util.TreeSet;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.enterprisepasswordsafe.engine.database.schema.AccessControlDAOInterface;
import com.enterprisepasswordsafe.engine.utils.DatabaseConnectionUtils;
import com.enterprisepasswordsafe.engine.utils.InvalidLicenceException;
import com.enterprisepasswordsafe.engine.utils.KeyUtils;
import com.enterprisepasswordsafe.proguard.ExternalInterface;

/**
 * Data access object for GroupAccessControl objects.
 */

public class GroupAccessControlDAO
    implements AccessControlDAOInterface<Group, GroupAccessControl>, ExternalInterface {

    /**
     * The fields needed to construct a GroupAccessControl from a ResultSet.
     */

    public static final String GAC_FIELDS = " gac.item_id, gac.mkey, gac.rkey, gac.group_id ";

    /**
     * The number of columns in the group access control data.
     */

    public static final int GAC_FIELD_COUNT = 1 + AccessControl.ACCESS_CONTROL_FIELD_COUNT;

    /**
     * The SQL to delete a GAC.
     */

    private static final String DELETE_SQL =
            "DELETE FROM group_access_control "
            + " WHERE group_id = ? "
            + "   AND item_id = ?";

    /**
     * The SQL to delete all GACs for an item.
     */

    private static final String DELETE_ALL_FOR_ITEM_SQL =
            "DELETE FROM group_access_control "
            + " WHERE item_id = ? AND group_id <> '"+Group.ADMIN_GROUP_ID+"'";

    /**
     * SQL To get the GAC allowing a user full access to a item.
     */

    private static final String GET_GROUP_FOR_FULL_GAC_SQL =
            "SELECT " + GAC_FIELDS
            + " FROM group_access_control gac, "
            + "      membership mem "
            + "WHERE mem.user_id = ? "
            + "  AND gac.item_id = ? "
            + "  AND gac.group_id = mem.group_id "
            + "  AND gac.rkey IS NOT NULL "
            + "  AND gac.mkey IS NOT NULL "
    		+ " ORDER BY gac.group_id";

    /**
     * SQL To get the GAC allowing a user full access to a item.
     */

    private static final String GET_GROUP_FOR_FULL_GAC_INCLUDING_DISABLED_SQL =
            "SELECT " + GAC_FIELDS
            + " FROM group_access_control gac, "
            + "      membership mem "
            + "WHERE mem.user_id = ? "
            + "  AND gac.item_id = ? "
            + "  AND gac.group_id = mem.group_id "
            + "  AND gac.rkey IS NOT NULL "
            + "  AND gac.mkey IS NOT NULL ";

    /**
     * SQL To get the GAC allowing a user read access to a item.
     */

    private static final String GET_GROUP_FOR_GAC_SQL =
            "SELECT " + GAC_FIELDS
            + "  FROM group_access_control gac, "
            + "       membership mem "
            + " WHERE mem.user_id = ? "
            + "   AND mem.group_id = gac.group_id "
            + "   AND gac.item_id = ? "
            + "   AND gac.rkey IS NOT NULL ";

    /**
     * SQL To get the GAC allowing users access to a item.
     */

    private static final String GET_GROUP_FOR_GAC_INCLUDING_DISABLED_SQL =
    		"SELECT "+ GAC_FIELDS
            + "  FROM group_access_control gac, "
            + "       membership mem "
            + "WHERE mem.user_id = ? "
            + "  AND gac.item_id = ? "
            + "  AND gac.group_id = mem.group_id "
            + "  AND gac.rkey IS NOT NULL "
            + "  AND gac.mkey IS NULL ";

    /**
     * SQL To get the GAC for a specific user and specific group.
     */

    private static final String GET_GAC_FOR_GROUP_SQL =
    		"SELECT "+ GAC_FIELDS
            + "  FROM group_access_control gac "
            + " WHERE gac.group_id = ? "
            + "   AND gac.item_id = ? "
            + "   AND gac.rkey IS NOT NULL ";


    /**
     * The SQL to get all group access controls for all groups with access to
     * this password.
     */

    private static final String GET_GAC_SUMMARIES_GAR_SQL =
              "SELECT gar.role"
            + "  FROM group_access_roles gar "
            + " WHERE gar.item_id = ? "
    		+ "   AND gar.actor_id = ?";

    /**
     * The SQL to get all group access controls for all groups with access to
     * this password.
     */

    private static final String GET_GAC_SUMMARIES_GAC_SQL =
              "SELECT gac.rkey, gac.mkey"
            + "  FROM group_access_control gac "
            + " WHERE gac.item_id = ? "
            + "   AND gac.group_id = ? "
            + "	  AND gac.rkey IS NOT NULL ";


    /**
     * The SQL statement to insert a group access control into the database.
     */

    private static final String WRITE_GAC_SQL =
            "INSERT INTO group_access_control(group_id, item_id, rkey, mkey) "
            + "                       VALUES (       ?,       ?,    ?,    ?)";
	/**
	 * Private constructor to prevent instantiation
	 */

	private GroupAccessControlDAO() {
		super();
	}


    /**
     * Gets a read group access control for a specific user and item.
     *
     * @param theUser The user to get the GAC for.
     * @param itemId The ID of the item to get the GAC for.
     *
     * @return The GAC for the user to access the item.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the GAC.
     * @throws UnsupportedEncodingException
     */

    public GroupAccessControl getReadGac(final User theUser, final String itemId)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_GROUP_FOR_GAC_SQL);
        try {
            ps.setString(1, theUser.getUserId());
            ps.setString(2, itemId);
            ps.setMaxRows(1);
            ResultSet rs = ps.executeQuery();
            try {
	            if (!rs.next()) {
	            	return null;
	            }

            	String groupId = rs.getString(4);
            	try {
	            	Group group = GroupDAO.getInstance().getByIdDecrypted(groupId, theUser);
	                return new GroupAccessControl(rs, 1, group);
            	} catch(GeneralSecurityException gse) {
            		Logger.getAnonymousLogger().log(Level.SEVERE, "Error accessing "+itemId+" for "+theUser.getUserId()+" via "+groupId);
            		return null;
            	}
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
        	DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Gets the group access control for a specific user and item.
     *
     * @param theUser The user to get the GAC for.
     * @param item The item to get the GAC for.
     *
     * @return The GAC for the user to access the item.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the GAC.
     * @throws UnsupportedEncodingException
     */

    public GroupAccessControl getGac(final User theUser, final AccessControledObject item)
        throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        return getGac(theUser, item.getId());
    }

    /**
     * Gets the group access control for a specific user and item.
     *
     * @param theUser The user to get the GAC for.
     * @param itemId The ID of the item to get the GAC for.
     *
     * @return The GAC for the user to access the item.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the GAC.
     * @throws UnsupportedEncodingException
     */

    public GroupAccessControl getGac(final User theUser, final String itemId)
        throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        return getGacWork(theUser, itemId, GET_GROUP_FOR_FULL_GAC_SQL, GET_GROUP_FOR_GAC_SQL);
    }

    /**
     * Gets the group access control for a specific user and item even if the
     * group involved has been disabled.
     *
     * @param theUser The user to get the GAC for.
     * @param item The item to get the GAC for.
     *
     * @return The GAC for the user to access the item.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the GAC.
     * @throws UnsupportedEncodingException
     */

    public GroupAccessControl getGacEvenIfDisabled(final User theUser,
    		final AccessControledObject item)
        throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        return getGacEvenIfDisabled(theUser, item.getId());
    }

    /**
     * Gets the group access control for a specific user and item even if the
     * group involved has been disabled.
     *
     * @param theUser The user to get the GAC for.
     * @param itemId The ID of the item to get the GAC for.
     *
     * @return The GAC for the user to access the item.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the GAC.
     * @throws UnsupportedEncodingException
     */

    public GroupAccessControl getGacEvenIfDisabled(final User theUser,
    		final String itemId)
        throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        return getGacWork(theUser, itemId,
                GET_GROUP_FOR_FULL_GAC_INCLUDING_DISABLED_SQL,
                GET_GROUP_FOR_GAC_INCLUDING_DISABLED_SQL);
    }

    /**
     * Gets the group access control for a specific user and item.
     *
     * @param theUser The user to get the GAC for.
     * @param itemId The ID of the item to get the GAC for.
     * @param fullSql The SQL to get read and write GACs.
     * @param readOnlySql The SQL to get read only GACs.
     *
     * @return The GAC for the user to access the item.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the GAC.
     * @throws UnsupportedEncodingException
     */

    private GroupAccessControl getGacWork(final User theUser,
    		final String itemId, final String fullSql,
    		final String readOnlySql)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        // Check for invalid parameters
        if (theUser == null || itemId == null) {
            return null;
        }

        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(fullSql);
        try {
            ps.setString(1, theUser.getUserId());
            ps.setString(2, itemId);
            ps.setMaxRows(1);
            ResultSet rs = ps.executeQuery();
            try {
	            if (rs.next()) {
	            	String groupId = rs.getString(4);
	            	Group group = GroupDAO.getInstance().getByIdDecrypted(groupId, theUser);
	                return new GroupAccessControl(rs, 1, group);
	            }
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
        	DatabaseConnectionUtils.close(ps);
        }

        ps = BOMFactory.getCurrentConntection().prepareStatement(readOnlySql);
        try {
            ps.setString(1, theUser.getUserId());
            ps.setString(2, itemId);
            ps.setMaxRows(1);
            ResultSet rs = ps.executeQuery();
            try {
	            if (rs.next()) {
	            	String groupId = rs.getString(4);
	            	Group group = GroupDAO.getInstance().getByIdDecrypted(groupId, theUser);
	                return new GroupAccessControl(rs, 1, group);
	            }
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
        	DatabaseConnectionUtils.close(ps);
        }

        return null;
    }

    /**
     * Gets the group access control for a specific user and group.
     *
     * @param user The user to get the GAC for.
     * @param group The group to get the GAC for.
     * @param item The item to get the GAC for.
     *
     * @return The GAC for the user to access the item.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the GAC.
     * @throws UnsupportedEncodingException
     */

    public GroupAccessControl getGac(final User user,
    		final Group group, final AccessControledObject item)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
    	if(item == null) {
    		return null;
    	}

    	return getGac(user, group, item.getId());
    }

    /**
     * Gets the group access control for a specific user and group.
     *
     * @param user The user to get the GAC for.
     * @param group The group to get the GAC for.
     * @param itemId The ID of the item to get the GAC for.
     *
     * @return The GAC for the user to access the item.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the GAC.
     * @throws UnsupportedEncodingException
     */

    public GroupAccessControl getGac(final User user,
    		final Group group, final String itemId)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
    	if(user == null || group == null || itemId == null) {
    		return null;
    	}

    	if( group.getAccessKey() == null ) {
    		Membership membership = MembershipDAO.getInstance().getMembership(user, group.getGroupId());
            group.updateAccessKey(membership);
    	}

        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_GAC_FOR_GROUP_SQL);
        try {
            ps.setString(1, group.getGroupId());
            ps.setString(2, itemId);
            ps.setMaxRows(1);
            ResultSet rs = ps.executeQuery();
            try {
	            if (rs.next()) {
	                return new GroupAccessControl(rs, 1, group);
	            }

	            return null;
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }


    /**
     * Gets the group access control for a group. The group must already have the access key set.
     *
     * @param group The group to get the AC for.
     * @param password The password to get the AC for.
     *
     * @return The GAC for the user to access the item.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the GAC.
     * @throws UnsupportedEncodingException
     */

    public GroupAccessControl getGac(final Group group, final Password password)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
    	if(password == null) {
    		return null;
    	}

    	return getGac(group, password.getId());
    }

    /**
     * Gets the group access control for a group. The group must already have the access key set.
     *
     * @param group The group to get the AC for.
     * @param passwordId The ID of the password to get the AC for.
     *
     * @return The GAC for the user to access the item.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the GAC.
     * @throws UnsupportedEncodingException
     */

    public GroupAccessControl getGac(final Group group, final String passwordId)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
    	if(group == null || passwordId == null) {
    		return null;
    	}

    	if( group.getAccessKey() == null ) {
    		throw new GeneralSecurityException("Attempt to decrypt group with encoded group");
    	}

        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_GAC_FOR_GROUP_SQL);
        try {
            ps.setString(1, group.getGroupId());
            ps.setString(2, passwordId);
            ps.setMaxRows(1);
            ResultSet rs = ps.executeQuery();
            try {
	            if (rs.next()) {
	                return new GroupAccessControl(rs, 1, group);
	            }
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
        	DatabaseConnectionUtils.close(ps);
        }

        return null;
    }

    /**
     * Delete this access control.
     *
     * @param gac The GroupAccessControl to delete.
     *
     * @throws SQLException Thrown if there is a problem accessing the data.
     */

    public void delete(final GroupAccessControl gac) throws SQLException {
        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_SQL);
        try {
            ps.setString(1, gac.getGroupId());
            ps.setString(2, gac.getItemId());
            ps.executeUpdate();
        } finally {
        	DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Delete this access control.
     *
     * @param aco The AccessControledObject to delete the GACs for.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    public void deleteAllForItem(AccessControledObject aco)
        throws SQLException {
    	PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_ALL_FOR_ITEM_SQL);
        try {
            ps.setString(1, aco.getId());
            ps.executeUpdate();
        } finally {
        	DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Create a group access control from an accessible object and a group.
     *
     * @param group The group to create the GAC for.
     * @param item The item to create the GAC for.
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException
     */

    public GroupAccessControl create(Group group, AccessControledObject item,
    		boolean allowRead, boolean allowModify)
    	throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
    	return create(group, item, allowRead, allowModify, true);
    }


    /**
     * Create a group access control from an accessible object and a group.
     *
     * @param group The group to create the GAC for.
     * @param item The item to create the GAC for.
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException
     */

    public GroupAccessControl create(Group group, AccessControledObject item,
    		boolean allowRead, boolean allowModify, boolean writeToDatabase)
    	throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
    	PrivateKey modifyKey = null;
    	if( allowModify ) {
    		modifyKey = item.getModifyKey();
    	}

    	GroupAccessControl gac =
    			new GroupAccessControl( group.getGroupId(), item.getId(), modifyKey, item.getReadKey() );
    	if(writeToDatabase) {
    		write(group, gac);
    	}
    	return gac;
    }

    /**
     * Store the GAC for a particular group.
     *
     * @param group The group to store the GAC for.
     * @param gac The GAC to store.
     *
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException
     */

    public void write(final Group group, final GroupAccessControl gac)
    	throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(WRITE_GAC_SQL);
        try {
            ps.setString(1,	gac.getGroupId());
            ps.setString(2,	gac.getItemId());
            ps.setBytes(3,	KeyUtils.encryptKey(gac.getReadKey(), group.getKeyEncrypter()));
            ps.setBytes(4, 	KeyUtils.encryptKey(gac.getModifyKey(), group.getKeyEncrypter()));
            ps.executeUpdate();
        } finally {
        	DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Get a sorted set of group access summaries for this password.
     *
     * @param item The AccessControledObject to get the AccessSummarys for.
     *
     * @return The Set of access summaries
     *
     * @throws SQLException
     *             Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException
     *             Thrown if there is a problem with the access credentials.
     * @throws UnsupportedEncodingException
     */
    public Set<AccessSummary> getSummaries(final AccessControledObject item)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        Set<AccessSummary> summaries = new TreeSet<AccessSummary>();

        Connection conn = BOMFactory.getCurrentConntection();
    	PreparedStatement gacPS = conn.prepareStatement(GET_GAC_SUMMARIES_GAC_SQL);
    	try {
        	PreparedStatement garPS = conn.prepareStatement(GET_GAC_SUMMARIES_GAR_SQL);
        	try {
	    		gacPS.setString(1, item.getId());
	    		garPS.setString(1, item.getId());

	    		for(Group thisGroup :  GroupDAO.getInstance().getAll()) {
		    		boolean canRead = false;
		    		boolean canModify = false;
		    		gacPS.setString(2, thisGroup.getGroupId());
		    		ResultSet rs = gacPS.executeQuery();
		    		try {
		    			if( rs.next() ) {
		    				rs.getString(1);	// Read the read key
		    				canRead = (rs.wasNull() == false);
		    				rs.getString(2);	// Read the modify key
		    				canModify = (rs.wasNull() == false);
		    			}
		    		} finally {
		    			DatabaseConnectionUtils.close(rs);
		    		}

		    		boolean canApproveRARequest = false;
		    		boolean canViewHistory = false;
		    		garPS.setString(2, thisGroup.getGroupId());
		    		rs = garPS.executeQuery();
		    		try {
		    			while( rs.next() ) {
		    				String role = rs.getString(1);
		    				if( rs.wasNull() ) {
		    					continue;
		    				}

		    				if( role.equals(AccessRole.APPROVER_ROLE) ) {
		    					canApproveRARequest = true;
		    				} else if ( role.equals(AccessRole.HISTORYVIEWER_ROLE) ) {
		    					canViewHistory = true;
		    				}
		    			}
		    		} finally {
		    			DatabaseConnectionUtils.close(rs);
		    		}

	            	AccessSummary gas =
	            		new AccessSummary(
	            				thisGroup.getGroupId(),
	            				thisGroup.getGroupName(),
	            				canRead,
	            				canModify,
	            				canApproveRARequest,
	            				canViewHistory
	        				);
	            	summaries.add(gas);
		    	}

	    		return summaries;
        	} finally {
        		DatabaseConnectionUtils.close(garPS);
        	}
    	} finally {
    		DatabaseConnectionUtils.close(gacPS);
    	}
    }

    /**
     * Updates a GAC in the database.
     *
     * @param group The group the GroupAccessControl is being updated for.
     * @param gac The group access control to store.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem during encryption.
     * @throws UnsupportedEncodingException
     * @throws InvalidLicenceException Thrown if the EPS licence is not valid.
     */

    public void update(final Group group, final GroupAccessControl gac)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
// TODO: Look at improving update
    	delete(gac);
    	write(group, gac);
    }

    //------------------------

    private static class InstanceHolder {
    	static final GroupAccessControlDAO INSTANCE = new GroupAccessControlDAO();
    }

    public static GroupAccessControlDAO getInstance() {
		return InstanceHolder.INSTANCE;
    }
}
