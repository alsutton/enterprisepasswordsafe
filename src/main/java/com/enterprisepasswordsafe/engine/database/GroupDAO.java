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
import java.util.*;

import com.enterprisepasswordsafe.engine.database.derived.GroupSummary;
import com.enterprisepasswordsafe.engine.utils.Cache;
import com.enterprisepasswordsafe.engine.utils.DatabaseConnectionUtils;
import com.enterprisepasswordsafe.engine.utils.IDGenerator;
import com.enterprisepasswordsafe.engine.utils.InvalidLicenceException;
import com.enterprisepasswordsafe.engine.utils.TokenizerUtils;
import com.enterprisepasswordsafe.proguard.ExternalInterface;
import org.apache.commons.csv.CSVRecord;

/**
 * Data access object for the group objects.
 */
public class GroupDAO implements ExternalInterface {
    /**
     * The columns holding group information.
     */

    public static final String GROUP_FIELDS = " grp.group_id, grp.group_name, grp.status ";

    /**
     * The SQL to get a particular group by its' ID.
     */

    private static final String GET_BY_ID_SQL = "SELECT " + GROUP_FIELDS +" FROM groups grp" + " WHERE grp.group_id = ?";

    /**
     * The SQL to get a particular group by its' ID (includes disabled groups).
     */

    private static final String GET_BY_ID_EVEN_IF_DISABLED_SQL = "SELECT "
            + GROUP_FIELDS + "  FROM groups grp " + " WHERE grp.group_id = ? AND grp.status < " + Group.STATUS_DELETED;

    /**
     * The SQL to get a particular group by its' name.
     */

    private static final String GET_BY_NAME_SQL = "SELECT " + GROUP_FIELDS
            + "  FROM groups grp " + " WHERE grp.group_name = ? AND grp.status = "+Group.STATUS_ENABLED;

    /**
     * The SQL statement to get all the available groups.
     */

    private static final String GET_ALL_GROUPS_SQL = "SELECT " + GROUP_FIELDS
            + "  FROM groups grp "
            + " WHERE grp.group_id != '0' "
            + "   AND grp.group_id != '1' "
            + "   AND grp.group_id != '2' "
            + "   AND grp.group_id != '3' "
            + "	  AND grp.status < " + Group.STATUS_DELETED
            + " ORDER BY grp.group_name ASC";

    /**
     * The SQL statement to get all the available groups.
     */

    private static final String GET_ALL_GROUP_IDS_SQL = "SELECT group_id "
            + "  FROM groups grp "
            + " WHERE grp.group_id != '0' "
            + "   AND grp.group_id != '1' "
            + "   AND grp.group_id != '2' "
            + "   AND grp.group_id != '3' "
            + "	  AND grp.status < " + Group.STATUS_DELETED
            + " ORDER BY grp.group_name ASC";

    /**
     * The SQL statement to get all the available enabled groups.
     */

    private static final String GET_ALL_ENABLED_GROUPS_SQL = "SELECT " + GROUP_FIELDS
            + "  FROM groups grp "
            + " WHERE grp.group_id != '0' "
            + "   AND grp.group_id != '1' "
            + "   AND grp.group_id != '2' "
            + "   AND grp.group_id != '3' "
            + "	  AND grp.status = " + Group.STATUS_ENABLED
            + " ORDER BY grp.group_name ASC";

    /**
     * The SQL write a groups details to the database.
     */

    private static final String WRITE_GROUP_SQL =
            "INSERT INTO groups(group_id, group_name, status)"
            + "          VALUES(       ?,          ?, "+Group.STATUS_ENABLED+")";

    /**
     * The SQL write a groups details to the database.
     */

    private static final String UPDATE_GROUP_SQL =
            "UPDATE groups SET group_name = ?, status = ? WHERE group_id = ?";

    /**
     * The SQL to count the number of members in a group.
     */

    private static final String COUNT_SQL = "SELECT count(*)  FROM membership  WHERE group_id = ?";

    /**
     * The SQL to count the number of members in a group.
     */

    private static final String MEMBER_LIST_SQL =
            "SELECT " + User.USER_FIELDS
            + " FROM application_users appusers, "
            + "     membership m "
            + " WHERE m.group_id = ? "
            + "   AND m.user_id = appusers.user_id "
            + "   AND appusers.user_id <> '0' "
            + "   AND (appusers.disabled is null OR appusers.disabled = 'N')"
            + " ORDER BY appusers.user_name ASC";

    /**
     * SQL to delete a group.
     */

    private static final String DELETE_SQL = "UPDATE groups SET status = "+Group.STATUS_DELETED+" WHERE group_id = ?";

    /**
     * SQL to delete the GACs for a group
     */

    private static final String DELETE_GAC_SQL = "DELETE FROM group_access_control WHERE group_id = ?";

    /**
     * SQL to delete the memberships for a group
     */

    private static final String DELETE_MEMBERSHIP_SQL = "DELETE FROM membership WHERE group_id = ?";


    /**
     * The SQL to get the user summary for a search
     */

    private static final String GET_SUMMARY_BY_SEARCH =
    		"SELECT   group_id, group_name FROM groups WHERE group_name like ? ";

    /**
	 * Cache for decrypted groups.
	 */

	private final Cache<String, Group> decryptedGroupCache = new Cache<String, Group>();

	/**
	 * Cache for groups.
	 */

	private final Cache<String, Group> groupCache = new Cache<String, Group>();

	/**
	 * Private constructor to prevent instantiation
	 */

	private GroupDAO() {
		super();
	}


    public void importGroup(final User theImporter, final CSVRecord record)
    	throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        Iterator<String> valueIterator = record.iterator();
        if (!valueIterator.hasNext()) {
            throw new GeneralSecurityException("No groupname specified.");
        }

        String groupName = valueIterator.next().trim();
        Group theGroup = create(theImporter, groupName);

        Group adminGroup = getAdminGroup(theImporter);
        while(valueIterator.hasNext()) {
            String memberName = valueIterator.next();
            User thisUser = UserDAO.getInstance().getByName(memberName);
            if (thisUser == null) {
                throw new GeneralSecurityException(memberName + " does not exist");
            }
            thisUser.decryptAdminAccessKey(adminGroup);
            MembershipDAO.getInstance().create(thisUser, theGroup);
        }
    }


    /**
     * Create a group.
     *
     * @param theCreator The user creating the group.
     * @param id The ID of the group to create.
     * @param groupName The name of the group to create.
     *
     * @return The newly created group.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem creating the group key
     * @throws UnsupportedEncodingException
     * @throws InvalidLicenceException Thrown if the system licence key is not valid.
     */

    public Group create(final User theCreator, final String id, final String groupName)
    	throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        Group theGroup = getByName(groupName);
        if (theGroup != null) {
            throw new GeneralSecurityException("The group already exists");
        }

        // Create the group and ensure that user 0 is a member.
        Group newGroup = new Group(id, groupName, true);
        write(newGroup);

        MembershipDAO mDAO = MembershipDAO.getInstance();
        mDAO.create(theCreator, newGroup);

        TamperproofEventLogDAO.getInstance().create(
        		TamperproofEventLog.LOG_LEVEL_GROUP_MANIPULATION,
        		theCreator,
        		"Created the group {group:" + newGroup.getGroupId() + "}",
        		true
    		);

        // Ensure the creating user is part of the group if they are not the
        // admin user.
        if (!theCreator.getUserId().equals(User.ADMIN_USER_ID)) {
        	mDAO.create(theCreator, newGroup);
        }

        return newGroup;
    }

    /**
     * Create a group.
     *
     * @param theCreator The user creating the group.
     * @param groupName The name of the group to create.
     *
     * @return The newly created group.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem creating the group key
     * @throws UnsupportedEncodingException
     * @throws InvalidLicenceException Thrown if the system licence key is not valid.
     */

    public Group create(final User theCreator, final String groupName)
    	throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        return create( theCreator, IDGenerator.getID(), groupName);
    }

    /**
     * Gets the admin group if it's possible to get the group from the given user.
     *
     * @param theUser The user to attempt to get the admin group for.
     *
     * @return The admin group (group 0), or null if the user does not have
     *         admin or sub-admin rights.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting data.
     * @throws UnsupportedEncodingException
     */

    public Group getAdminGroup(final User theUser)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        // Get the admin group either directly (if the user is an admin),
        // or indirectly (if the user is only a sub-admin).
        Group adminGroup = getById(Group.ADMIN_GROUP_ID);
        if (theUser.isAdministrator()) {
            Membership adminMembership = MembershipDAO.getInstance().getMembership(theUser, Group.ADMIN_GROUP_ID);
            adminGroup.updateAccessKey(adminMembership);
        } else if (theUser.isSubadministrator()) {
            Membership subAdminMembership =
            	MembershipDAO.getInstance().getMembership(theUser, Group.SUBADMIN_GROUP_ID);
            Group subAdminGroup = getById(Group.SUBADMIN_GROUP_ID);
            subAdminGroup.updateAccessKey(subAdminMembership);
            adminGroup.setAccessKey(subAdminGroup.getAccessKey());
        } else {
            return null;
        }

        return adminGroup;
    }

    /**
     * Gets the data about an individual group if it is enabled.
     *
     * @param id The ID of the group to get.
     *
     * @return The group object, or null if the user does not exist.
     *
     * @throws SQLException Thrown if tehre is a problem getting the data from the database.
     */

    public Group getByIdEvenIfDisabled(final String id)
            throws SQLException {
        return getByIdWork(GET_BY_ID_EVEN_IF_DISABLED_SQL, id);
    }

    /**
     * Gets the data about an individual group if it is enabled.
     *
     * @param id The ID of the group to get.
     *
     * @return The group object, or null if the user does not exist.
     *
     * @throws SQLException Thrown if tehre is a problem getting the data from the database.
     */

    public Group getById(final String id) throws SQLException {
        return getByIdWork(GET_BY_ID_SQL, id);
    }


    /**
     * Gets the data about an individual group using the SQL provided.
     *
     * @param sql The SQL to use.
     * @param id The ID of the group to get.
     *
     * @return The group object, or null if the user does not exist.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    public Group getByIdWork(final String sql, final String id)
            throws SQLException {
    	Group group;
    	synchronized(groupCache) {
	    	group = groupCache.get(id);
	    	if(group != null) {
	    		return group;
	    	}
    	}

        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql);
        try {
            ps.setString(1, id);
            ps.setMaxRows(1);

            ResultSet rs = ps.executeQuery();
            try {
	            if (!rs.next()) {
	            	return null;
	            }

	            group = new Group(rs, 1);
	        	synchronized(groupCache) {
	        		groupCache.put(id, group);
	        	}
	            return group;
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Gets a group including it's decrypted group key.
     *
     * @param groupId The id of the group to get
     * @param user The user fetching the group.
     *
     * @return The group with it's decrypted key, or null if the group is unavailable
     *  to the user.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting data.
     * @throws UnsupportedEncodingException
     */

    public Group getByIdDecrypted(final String groupId, final User user)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
    	Group theGroup;
    	synchronized(decryptedGroupCache) {
    		theGroup = decryptedGroupCache.get(groupId);
	    	if( theGroup != null ) {
	    		return theGroup;
	    	}
    	}

    	if( user.isAdministrator() ) {
    		theGroup = getByIdEvenIfDisabled(groupId);
    	} else {
    		theGroup = getById(groupId);
    	}
    	if( theGroup == null || theGroup.getStatus() == Group.STATUS_DELETED) {
    		return null;
    	}

    	Membership mem = MembershipDAO.getInstance().getMembership(user, groupId);
    	if( mem == null ) {
    		return null;
    	}

    	theGroup.updateAccessKey(mem);

    	synchronized(decryptedGroupCache) {
    		decryptedGroupCache.put(groupId, theGroup);
    	}
    	return theGroup;
    }

    /**
     * Gets the data about an individual group.
     *
     * @param name The Name of the group to get.
     *
     * @return The group object, or null if the user does not exist.
     *
     * @throws SQLException thrown if there is a problem accessing the database.
     */

    public Group getByName(final String name)
            throws SQLException {
        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_BY_NAME_SQL);
        try {
            ps.setString(1, name);

            ResultSet rs = ps.executeQuery();
            try {
	            if (rs.next()) {
	                return new Group(rs, 1);
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
     * Writes a group to the database.
     *
     * @param group The group to write.
     *
     * @throws SQLException Thrown if there is a problem accessing thda database.
     * @throws GeneralSecurityException Thrown if there is a problem encrypting the user data.
     * @throws UnsupportedEncodingException
     * @throws InvalidLicenceException Thrown if the licence is not valid.
     */

    public void write(final Group group)
        throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(WRITE_GROUP_SQL);
        try {
            ps.setString(1, group.getGroupId());
            ps.setString(2, group.getGroupName());
            ps.executeUpdate();
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * updates a group in the database.
     *
     * @param group The group to update.
     *
     * @throws SQLException Thrown if there is a problem accessing thda database.
     * @throws GeneralSecurityException Thrown if there is a problem encrypting the user data.
     * @throws UnsupportedEncodingException
     * @throws InvalidLicenceException Thrown if the licence is not valid.
     */

    public void update(final Group group)
        throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(UPDATE_GROUP_SQL);
        try {
            ps.setString(1, group.getGroupName());
            ps.setInt(2, group.getStatus());
            ps.setString(3, group.getGroupId());
            ps.executeUpdate();
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }


    /**
     * Gets all groups (including disabled ones).
     *
     * @return A List of all Groups.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    public List<Group> getAll()
    	throws SQLException {
    	return getAllWork(GET_ALL_GROUPS_SQL);
    }

    /**
     * Gets all groups (including disabled ones).
     *
     * @return A List of all Groups.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    public List<Group> getAllEnabled()
    	throws SQLException {
    	return getAllWork(GET_ALL_ENABLED_GROUPS_SQL);
    }

    /**
     * Perform a SQL query and return a List of Groups representing the results.
     *
     * @return A List of all Groups.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    private List<Group> getAllWork( String sql)
    	throws SQLException {
        List<Group> groups = new ArrayList<Group>();

        PreparedStatement stmt = BOMFactory.getCurrentConntection().prepareStatement(sql);
        try {
            ResultSet rs = stmt.executeQuery();
            try {
	            while (rs.next()) {
	                groups.add(new Group(rs, 1));
	            }

	            return groups;
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
            DatabaseConnectionUtils.close(stmt);
        }
    }

    /**
     * Gets all the group IDs.
     *
     * @return A List of all group IDs.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    public List<String> getAllIds()
    	throws SQLException {
        List<String> groups = new ArrayList<String>();

        PreparedStatement stmt = BOMFactory.getCurrentConntection().prepareStatement(GET_ALL_GROUP_IDS_SQL);
        try {
            ResultSet rs = stmt.executeQuery();
            try {
	            while (rs.next()) {
	                groups.add(rs.getString(1));
	            }

	            return groups;
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
            DatabaseConnectionUtils.close(stmt);
        }
    }

    /**
     * Counts the number of members in a group.
     *
     * @param group The group to count the number of members.
     *
     * @return The number of users in the group.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    public int countMembers(final Group group) throws SQLException {
        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(COUNT_SQL);
        try {
            ps.setString(1, group.getGroupId());
            ResultSet rs = ps.executeQuery();
            try {
	            if (rs.next()) {
	                return rs.getInt(1);
	            }

	            return -1;
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Gets the members of this group.
     *
     * @param group The Group to get the list of members of.
     *
     * @return a List of User objects representing the members of the group.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    public List<User> getMemberList(final Group group) throws SQLException {
        List<User> members = new ArrayList<User>();

        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(MEMBER_LIST_SQL);
        try {
            ps.setString(1, group.getGroupId());

            ResultSet rs = ps.executeQuery();
            try {
	            while (rs.next()) {
	                members.add(new User(rs, 1));
	            }

	            return members;
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Delete a group.
     *
     * @param group The group to delete.
     */

    public void delete( final Group group )
    	throws SQLException {
    	String theGroupId = group.getGroupId();

    	PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_SQL);
    	try {
    		ps.setString(1, theGroupId);
    		ps.executeUpdate();
    	} finally {
    		DatabaseConnectionUtils.close(ps);
    	}

    	ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_GAC_SQL);
    	try {
    		ps.setString(1, theGroupId);
    		ps.executeUpdate();
    	} finally {
    		DatabaseConnectionUtils.close(ps);
    	}

    	ps = BOMFactory.getCurrentConntection().prepareStatement(DELETE_MEMBERSHIP_SQL);
    	try {
    		ps.setString(1, theGroupId);
    		ps.executeUpdate();
    	} finally {
    		DatabaseConnectionUtils.close(ps);
    	}
    }

    /**
     * Get the summary of the first 10 users which contain a specified search string
     *
     * @param searchQuery The query to search for
     * @return The summaries
     *
     * @throws SQLException
     *             Thrown if there is a problem accessing the database.
     */

    public List<GroupSummary> getSummaryBySearch(String searchQuery)
        throws SQLException {
    	synchronized( this ) {
    		List<GroupSummary> results= new ArrayList<GroupSummary>();

    		if(searchQuery == null) {
    			searchQuery = "%";
    		} else if(searchQuery.indexOf('%') == -1) {
    			searchQuery += "%";
    		}

	        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_SUMMARY_BY_SEARCH);
	        try {
	            ps.setString(1, searchQuery);

	            ResultSet rs = ps.executeQuery();
	            try {
		            while(rs.next()) {
			            results.add( new GroupSummary(rs.getString(1), rs.getString(2)) );
		            }

		            return results;
		        } finally {
		            DatabaseConnectionUtils.close(rs);
		        }
	        } finally {
	            DatabaseConnectionUtils.close(ps);
	        }
    	}
    }

    /**
     * Method to see if a group exists.
     *
     * @param groupName The name of the group to look for.
     * @return true if the group exists, false if not.
     *
     * @throws SQLException Exception thrown if there is a problem accessing the database
     */

    public boolean nameExists(String groupName) throws SQLException {
    	return (getByName(groupName) != null);
    }

    /**
     * Method to see if a group exists.
     *
     * @param groupId The id of the group to look for.
     * @return true if the group exists, false if not.
     *
     * @throws SQLException Exception thrown if there is a problem accessing the database
     */

    public boolean idExists(String groupId) throws SQLException {
    	return getById(groupId)!=null;
    }

    //------------------------

    private static final class InstanceHolder {
    	static final GroupDAO INSTANCE = new GroupDAO();
    }

    public static GroupDAO getInstance() {
    	return InstanceHolder.INSTANCE;
    }
}
