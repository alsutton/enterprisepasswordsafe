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

import com.enterprisepasswordsafe.engine.users.UserClassifier;
import com.enterprisepasswordsafe.engine.utils.IDGenerator;
import org.apache.commons.csv.CSVRecord;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.Iterator;
import java.util.List;

/**
 * Data access object for the group objects.
 */
public class GroupDAO extends GroupStoreManipulator {

    /**
     * The clause for excluding reserved system groups
     */

    private static final String EXCLUDE_RESERVED_GROUP_CLAUSE =
            "grp.group_id != '0' AND grp.group_id != '1' AND grp.group_id != '2' AND grp.group_id != '3'";

    /**
     * The SQL to get a particular group by its' ID.
     */

    private static final String GET_BY_ID_SQL = "SELECT " + GROUP_FIELDS +" FROM groups grp" + " WHERE grp.group_id = ?";

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
            + " WHERE  "
            + "	  AND grp.status < " + Group.STATUS_DELETED
            + " ORDER BY grp.group_name ASC";

    /**
     * The SQL statement to get all the available groups.
     */

    private static final String GET_ALL_GROUP_IDS_SQL = "SELECT group_id FROM groups grp "
            + " WHERE " + EXCLUDE_RESERVED_GROUP_CLAUSE+" AND grp.status < " + Group.STATUS_DELETED
            + " ORDER BY grp.group_name ASC";

    /**
     * The SQL statement to get all the available enabled groups.
     */

    private static final String GET_ALL_ENABLED_GROUPS_SQL = "SELECT " + GROUP_FIELDS+ "  FROM groups grp "
            + " WHERE " + EXCLUDE_RESERVED_GROUP_CLAUSE + " AND grp.status = " + Group.STATUS_ENABLED
            + " ORDER BY grp.group_name ASC";

    /**
     * The SQL write a groups details to the database.
     */

    private static final String WRITE_GROUP_SQL =
            "INSERT INTO groups(group_id, group_name, status)"
            + "          VALUES(       ?,          ?, "+Group.STATUS_ENABLED+")";

    /**
     * The SQL to count the number of members in a group.
     */

    private static final String COUNT_SQL = "SELECT count(*)  FROM membership  WHERE group_id = ?";

    /**
     * The SQL to get the user summary for a search
     */

    private static final String GET_SUMMARY_BY_SEARCH =
    		"SELECT " + GROUP_FIELDS + " FROM groups WHERE group_name like ? ";

	private UserClassifier userClassifier = new UserClassifier();

	/**
	 * Private constructor to prevent instantiation
	 */

	private GroupDAO() {
		super(GET_BY_ID_SQL, GET_BY_NAME_SQL, COUNT_SQL);
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

        TamperproofEventLogDAO.getInstance().create(TamperproofEventLog.LOG_LEVEL_GROUP_MANIPULATION,
        		theCreator, "Created the group {group:" + newGroup.getGroupId() + "}", true);

        // Ensure the creating user is part of the group if they are not the
        // admin user.
        if (!userClassifier.isMasterAdmin(theCreator)) {
        	mDAO.create(theCreator, newGroup);
        }

        return newGroup;
    }

    public Group create(final User theCreator, final String groupName)
    	throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        return create( theCreator, IDGenerator.getID(), groupName);
    }

    public Group getAdminGroup(final User theUser)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        // Get the admin group either directly (if the user is an admin),
        // or indirectly (if the user is only a sub-admin).
        Group adminGroup = getById(Group.ADMIN_GROUP_ID);
        if (userClassifier.isAdministrator(theUser)) {
            Membership adminMembership = MembershipDAO.getInstance().getMembership(theUser, Group.ADMIN_GROUP_ID);
            adminGroup.updateAccessKey(adminMembership);
        } else if (userClassifier.isSubadministrator(theUser)) {
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

    public Group getByIdDecrypted(final String groupId, final User user)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
    	Group theGroup = userClassifier.isAdministrator(user) ?
                UnfilteredGroupDAO.getInstance().getById(groupId) : getById(groupId);
    	if( theGroup == null || theGroup.getStatus() == Group.STATUS_DELETED) {
    		return null;
    	}

    	Membership mem = MembershipDAO.getInstance().getMembership(user, groupId);
    	if( mem == null ) {
    		return null;
    	}

    	theGroup.updateAccessKey(mem);

    	return theGroup;
    }

    public void write(final Group group)
        throws SQLException {
        runResultlessParameterisedSQL(WRITE_GROUP_SQL, group.getGroupId(), group.getGroupName());
    }

    public List<Group> getAll()
    	throws SQLException {
    	return getMultiple(GET_ALL_GROUPS_SQL);
    }

    public List<Group> getAllEnabled()
    	throws SQLException {
    	return getMultiple(GET_ALL_ENABLED_GROUPS_SQL);
    }

    public List<String> getAllIds()
    	throws SQLException {
        return getFieldValues(GET_ALL_GROUP_IDS_SQL);
    }

    public List<Group> searchNames(String searchQuery)
        throws SQLException {
        if(searchQuery == null) {
            searchQuery = "%";
        } else if(searchQuery.indexOf('%') == -1) {
            searchQuery += "%";
        }

        return getMultiple(GET_SUMMARY_BY_SEARCH, searchQuery);
    }

    public boolean nameExists(String groupName) throws SQLException {
    	return (getByName(groupName) != null);
    }

    public boolean idExists(String groupId) throws SQLException {
    	return getById(groupId) != null;
    }

    //------------------------

    private static final class InstanceHolder {
    	static final GroupDAO INSTANCE = new GroupDAO();
    }

    public static GroupDAO getInstance() {
    	return InstanceHolder.INSTANCE;
    }
}
