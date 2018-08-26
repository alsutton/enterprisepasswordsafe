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

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.enterprisepasswordsafe.engine.database.actions.PasswordAction;
import com.enterprisepasswordsafe.engine.database.actions.password.ExpiringAccessiblePasswordsAction;
import com.enterprisepasswordsafe.engine.database.derived.ExpiringAccessiblePasswords;
import com.enterprisepasswordsafe.engine.database.derived.PasswordSummary;
import com.enterprisepasswordsafe.engine.utils.*;
import com.enterprisepasswordsafe.proguard.ExternalInterface;
import org.apache.commons.csv.CSVRecord;

/**
 * Data access object for passwords.
 */
public final class PasswordDAO
        extends PasswordStoreManipulator
        implements ExternalInterface {

	/**
	 * Empty string used for null password summaries.
	 */

	private static final String EMPTY_STRING = "";

    /**
     * The default number of days before expiry when a warning is produced.
     */

    private static final int DEFAULT_PASSWORD_EXPIRY_WARNING_DAYS = 7;

    /**
     * The length of a permission header on an import line.
     */

    private static final int PERMISSION_HEADER_LENGTH = 3;

    /**
     * SQL to check if the restriction is in use.
     */

    private static final String USE_CHECK_SQL =
    		"SELECT " + PASSWORD_FIELDS + " FROM passwords pass WHERE pass.restriction_id = ?";

    /**
     * The SQL statement to get a password from an ID.
     */

    private static final String GET_BY_ID_SQL = "SELECT " + PASSWORD_FIELDS
            + "  FROM passwords pass" + " WHERE pass.password_id = ? "
            + "   AND (pass.enabled is null OR pass.enabled = 'Y')";

    /**
     * Selects all of the available locations from the database.
     */

    private static final String GET_ALL_FOR_LOCATION_SQL =
            "SELECT  "+ PASSWORD_FIELDS + "  FROM passwords pass " +
            " WHERE (pass.enabled is null OR pass.enabled = 'Y')" +
            "   AND pass.ptype = 0" +
            "   AND location_id = ?";

    /**
     * The SQL to get all the active passwords to be acted on.
     */

    private static final String GET_ALL_PASSWORDS_FOR_ACTION_BY_USER_SQL =
            "SELECT " + PASSWORD_FIELDS
            + "  FROM passwords             pass, "
            + "       user_access_control   uac "
            + " WHERE uac.user_id = ?"
            + "   AND uac.item_id = pass.password_id"
            + "   AND (pass.enabled is null OR pass.enabled = 'Y')";

    /**
     * The SQL to get all the active passwords to be acted on.
     */

    private static final String GET_ALL_PASSWORDS_FOR_ACTION_BY_GROUP_SQL =
            "SELECT " + PASSWORD_FIELDS
            + "  FROM passwords             pass, "
            + "       group_access_control  gac, "
            + "       membership            mem "
            + " WHERE mem.user_id  = ?"
            + "   AND mem.group_id    = gac.group_id "
            + "   AND gac.item_id = pass.password_id "
            + "   AND (pass.enabled is null OR pass.enabled = 'Y')";

    /**
     * The SQL to search for password ids and usernames which match a search location
     */

    private static final String SEARCH_ALL_PASSWORDS_FOR_LOCATIONS_BY_USER_SQL =
            "SELECT   pass.password_id, pass.password_data "
            + "  FROM passwords             pass, "
            + "       user_access_control   uac "
            + " WHERE uac.user_id = ?"
            + "   AND uac.item_id = pass.password_id"
            + "   AND (pass.enabled is null OR pass.enabled = 'Y')"
            + "   AND pass.location_id = ? ";

    /**
     * The SQL to get all the active passwords to be acted on.
     */

    private static final String SEARCH_ALL_PASSWORDS_FOR_LOCATIONS_BY_GROUP_SQL =
            "SELECT   pass.password_id, pass.password_data, gac.group_id "
            + "  FROM passwords             pass, "
            + "       group_access_control  gac, "
            + "       membership            mem "
            + " WHERE mem.user_id  = ?"
            + "   AND mem.group_id    = gac.group_id "
            + "   AND gac.item_id = pass.password_id "
            + "   AND (pass.enabled is null OR pass.enabled = 'Y')"
    		+ "   AND pass.location_id = ? ";

    /**
     * The SQL to get all the active passwords to be acted on.
     */

    private static final String GET_ALL_PASSWORDS_FOR_ACTION_BY_USER_EVEN_IF_DISABLED_SQL =
            "SELECT " + PASSWORD_FIELDS
            + "  FROM passwords             pass, "
            + "       user_access_control   uac "
            + " WHERE uac.user_id = ?"
            + "   AND uac.item_id = pass.password_id";

    /**
     * The SQL to get all the active passwords to be acted on.
     */

    private static final String GET_ALL_PASSWORDS_FOR_ACTION_BY_GROUP_EVEN_IF_DISABLED_SQL =
            "SELECT " + PASSWORD_FIELDS
            + "  FROM passwords             pass, "
            + "       group_access_control  gac, "
            + "       membership            mem "
            + " WHERE mem.user_id = ?"
            + "   AND mem.group_id    = gac.group_id "
            + "   AND gac.item_id = pass.password_id ";

    /**
     * Get all of the passwords summary details in the database with the
     * associated admin gac key.
     */

    private static final String GET_ALL_SUMMARY_DETAILS =
    	"SELECT pass.password_id, pass.password_data, " +
    	"        gac.item_id, gac.mkey, gac.rkey, gac.group_id "+
    	"  FROM passwords pass, " +
    	"		group_access_control gac "+
    	" WHERE pass.password_id = gac.item_id " +
    	"   AND gac.group_id = '"+Group.ADMIN_GROUP_ID+"'";

    /**
     * The SQL to get the email addresses of users who have access to this
     * password.
     */

    private static final String EMAILS_WITH_ACCESS_VIA_UAC = "SELECT users.email "
            + "  FROM application_users users, "
            + "       user_access_control uac "
            + " WHERE uac.item_id = ? "
            + "   AND uac.rkey IS NOT NULL "
            + "   AND uac.user_id = users.user_id "
            + "   AND users.disabled is null ";

    /**
     * The SQL to get the email addresses of users in groups which have access
     * to this password.
     */

    private static final String EMAILS_WITH_ACCESS_VIA_GAC = "SELECT users.email "
            + "  FROM application_users users, "
            + "       group_access_control gac, "
            + "       membership mem, "
            + "       groups grp "
            + " WHERE gac.item_id = ? "
            + "   AND gac.rkey IS NOT NULL "
            + "   AND gac.group_id = grp.group_id "
            + "  AND  grp.status = " + Group.STATUS_ENABLED
            + "   AND gac.group_id = mem.group_id "
            + "   AND mem.user_id = users.user_id "
            + "   AND users.disabled is null ";

    /**
     * The SQL to write a new password into the database.
     */

    private static final String WRITE_PASSWORD_SQL =
            "INSERT INTO passwords"
            + "(password_id, enabled, audited, history_stored, restriction_id, ra_enabled, "
            + "		ra_approvers, ra_blockers, ptype, location_id, password_data  )"
            + " VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )";

    /**
     * SQL to fetch the id and expiry date for the passwords.
     */

    private static final String GET_EXPIRY_DETAILS_SQL =
    	"SELECT password_id, password_data FROM passwords";

	/**
	 * private constructor to prevent instantiation.
	 */

	private PasswordDAO( ) {
		super(GET_BY_ID_SQL, null, null);
	}

	/**
	 * Store a new password creating an AccessControl for the admin group and the user.
	 *
	 * @param thePassword The password to store.
	 * @param creator The user creating the password.
	 *
	 * @throws GeneralSecurityException
	 * @throws SQLException
	 * @throws IOException
	 *
	 */

	public UserAccessControl storeNewPassword( final Password thePassword, final User creator )
		throws SQLException, GeneralSecurityException, IOException {
        Group adminGroup = GroupDAO.getInstance().getAdminGroup(creator);
        if (adminGroup == null) {
            throw new GeneralSecurityException("You can not create new passwords.");
        }

        GroupAccessControlDAO gacDAO = GroupAccessControlDAO.getInstance();
    	GroupAccessControl gac = gacDAO.create(adminGroup, thePassword, true, true, false);

        write(thePassword, gac);

        gacDAO.write(adminGroup, gac);
        return UserAccessControlDAO.getInstance().create(creator, thePassword, true, true);
	}

    /**
     * Gets the data about an individual password and decrypts it for
     * the user.
     *
     * @param id
     *            The ID of the password to get.
     *
     * @return The Password object, or null if the user does not exist.
     *
     * @throws SQLException
     *             Thrown if there is a problem getting the password.
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException
     */

    public String getSummaryById(User user, final String id)
            throws SQLException, IOException, GeneralSecurityException {
        return getSummaryById( AccessControlDAO.getInstance().getReadAccessControl(user, id), id );
    }

    /**
     * Gets the data about an individual password and decrypts it for
     * the user.
     *
     * @param id
     *            The ID of the password to get.
     *
     * @return The Password object, or null if the user does not exist.
     *
     * @throws SQLException
     *             Thrown if there is a problem getting the password.
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException
     */

    public String getSummaryById(AccessControl ac, final String id)
            throws SQLException, IOException, GeneralSecurityException {
        if( ac == null )
        	return EMPTY_STRING;

        Password password = getById(id, ac);
        if(password != null) {
        	return password.toString();
        }

        return EMPTY_STRING;
    }

    /**
     * Gets the data about an individual password and decrypts it for
     * the user.
     *
     * @param id
     *            The ID of the password to get.
     *
     * @return The Password object, or null if the user does not exist.
     *
     * @throws SQLException
     *             Thrown if there is a problem getting the password.
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException
     */

	public Password getById(final User user, final String id)
            throws SQLException, IOException, GeneralSecurityException {
        AccessControl ac = AccessControlDAO.getInstance().getReadAccessControl(user, id);
        if( ac == null )
        	return null;

        return getById(id, ac);
    }

    /**
     * Gets the data about an individual password and decrypts it using the user
     * details supplied.
     *
     * @param user The user attempting to get the password.
     * @param id The ID of the password to get.
     *
     * @return The Password object, or null if the user does not exist.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem with the access credentials.
     * @throws UnsupportedEncodingException
     */

	public Password getByIdForUser(final User user, final String id)
            throws SQLException, GeneralSecurityException, IOException {
    	Password thePassword;
    	if( user.isAdministrator() || user.isSubadministrator()) {
    		thePassword = UnfilteredPasswordDAO.getInstance().getById(user, id);
    	} else {
    		thePassword = getById(user, id);
    	}
        return thePassword;
    }

    /**
     * Create a password from an imported set of information.
     *
     * @param theCreator The user who is creating the password.
     * @param username The username associated with the password.
     * @param password The password itself.
     * @param location The location of the password.
     * @param notes The notes associated with the password.
     * @param audit Whether or not this password is audited.
     * @param history Whether or not the history is stored for this password.
     * @param expiry The expiry date for the password.
     * @param parentNode The node under which the password will be stored.
     * @param restrictionId The ID of the restriction for this password.
     * @param raEnabled If this is a restricted access password or not (true = ra enabled).
     * @param raApprovers The number of approvers required to access the password.
     * @param raBlockers The number of blockers required to block access to the password.
     * @param customFields The custom fields for the password.
     *
     * @return The created password.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the data.
     * @throws InvalidLicenceException Thrown if the current EPS licence is invalid.
     * @throws IOException Thrown if there is an IOException
     */

    public Password create(final User theCreator, final Group adminGroup,
            final String username, final String password, final String location,
            final String notes, final int audit, final boolean history,
            final long expiry, final String parentNode, final String restrictionId,
            final boolean raEnabled, final int raApprovers, final int raBlockers,
            final int type, Map<String,String> customFields)
            throws SQLException, GeneralSecurityException, IOException {
        Password newPassword = new Password(username, password, location, notes, Password.AUDITING_FULL, history, expiry);
        newPassword.setPasswordType(type);
        newPassword.setRestrictionId(restrictionId);
        newPassword.setRaEnabled(raEnabled);
        newPassword.setRaBlockers(raBlockers);
        newPassword.setRaApprovers(raApprovers);
        newPassword.setAuditLevel(audit);
        newPassword.setCustomFields(customFields);

        UserAccessControl newUac =
        		UserAccessControlDAO.getInstance().create(theCreator, newPassword, true, true, false);

        write(newPassword, newUac);

        UserAccessControlDAO.getInstance().write(newUac, theCreator);

        HierarchyNode node = new HierarchyNode(newPassword.getId(), parentNode, HierarchyNode.OBJECT_NODE);
        HierarchyNodeDAO.getInstance().store(node);

        if( adminGroup != null ) {
            GroupAccessControlDAO.getInstance().create(adminGroup, newPassword, true, true);
        	setDefaultPermissions(newPassword, parentNode, adminGroup);

	    	boolean sendEmail = ((newPassword.getAuditLevel() & Password.AUDITING_EMAIL_ONLY)!=0);
	        TamperproofEventLogDAO.getInstance().create(
					TamperproofEventLog.LOG_LEVEL_OBJECT_MANIPULATION,
	        				theCreator,
	        				newPassword,
	        				"Created the password.",
	        				sendEmail
					);
        }

        return newPassword;
    }

    /**
     * Sets the permissions on a password from the hierarchy defaults
     * @throws GeneralSecurityException
     * @throws SQLException
     * @throws UnsupportedEncodingException
     */

    private void setDefaultPermissions(final Password newPassword, final String parentNodeId, final Group adminGroup)
    		throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
        Map<String,String> uPerms = new HashMap<>();
        Map<String,String> gPerms = new HashMap<>();
        HierarchyNodeDAO.getInstance().getCombinedDefaultPermissionsForNode(parentNodeId, uPerms, gPerms);

        for(Map.Entry<String, String> thisEntry : uPerms.entrySet()) {
        	String userId = thisEntry.getKey();
        	User theUser = UserDAO.getInstance().getByIdDecrypted(userId, adminGroup);
        	if( theUser == null ) {
        		continue;
        	}

        	boolean allowRead = false;
        	boolean allowModify = false;
        	String permissions = thisEntry.getValue();
        	if			( permissions.equals("1") ) {
        		allowRead = true;
        	} else if	( permissions.equals("2") ) {
        		allowRead = true;
        		allowModify = true;
        	}

        	UserAccessControlDAO.getInstance().create(theUser, newPassword, allowRead, allowModify);
        }

        final User adminUser = UserDAO.getInstance().getAdminUser(adminGroup);
        for(Map.Entry<String,String> thisEntry : gPerms.entrySet()) {
        	final String groupId = thisEntry.getKey();
        	Group theGroup = GroupDAO.getInstance().getByIdDecrypted(groupId, adminUser);
        	if( theGroup == null ) {
        		continue;
        	}

        	boolean allowRead = false;
        	boolean allowModify = false;
        	final String permissions = thisEntry.getValue();
        	if			( permissions.equals("1") ) {
        		allowRead = true;
        	} else if	( permissions.equals("2") ) {
        		allowRead = true;
        		allowModify = true;
        	}

        	GroupAccessControlDAO.getInstance().create(theGroup, newPassword, allowRead, allowModify);
        }
    }

    /**
     * Stores a password in the database and creates a GAC for the admin group
     * to access it.
     *
     * @param password The password to store.
     * @param group The group for which the GAC should be created allow access.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the data.
     * @throws IOException Thrown if there is an IOException
     */

    public void write(final Password password, final Group group)
            throws SQLException, GeneralSecurityException, IOException {
    	GroupAccessControl gac = GroupAccessControlDAO.getInstance().create(group, password, true, true);
        GroupAccessControlDAO.getInstance().write(group, gac);

        write(password, gac);
    }

    /**
     * Stores a password in the database using the given AccessControl.
     *
     * @param password The password to store.
     * @param ac The access control to store the password with.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the data.
     * @throws IOException Thrown if there is an IOException
     */

    public void write(final Password password, final AccessControl ac)
        throws SQLException, GeneralSecurityException, IOException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(WRITE_PASSWORD_SQL)) {
            int idx = 1;
            ps.setString(idx++, password.getId());
            if (password.isEnabled()) {
                ps.setString(idx++, "Y");
            } else {
                ps.setString(idx++, "N");
            }
            if (password.getAuditLevel() == Password.AUDITING_FULL) {
                ps.setString(idx++, "Y");
            } else if (password.getAuditLevel() == Password.AUDITING_LOG_ONLY) {
                ps.setString(idx++, "L");
            } else {
                ps.setString(idx++, "N");
            }
            if (password.isHistoryStored()) {
                ps.setString(idx++, "Y");
            } else {
                ps.setString(idx++, "N");
            }
            ps.setString(idx++, password.getRestrictionId());
            if( password.isRaEnabled() ) {
            	ps.setString(idx++, "Y");
            } else {
            	ps.setString(idx++, "N");
            }
            ps.setInt(idx++, password.getRaApprovers());
            ps.setInt(idx++, password.getRaBlockers());
            ps.setInt(idx++, password.getPasswordType());
            ps.setString(idx++, LocationDAO.getInstance().getId(password.getLocation()));
            ps.setBytes(idx, PasswordUtils.encrypt(password, ac));

            ps.executeUpdate();

            // Write the password with the data encrypted
            if (password.isHistoryStored()) {
            	HistoricalPasswordDAO.getInstance().writeHistoryEntry(password, ac);
            }
        }
    }

    /**
     * Import a password from a CSVRecord.
     *
     * @param theImporter The user who is importing the password.
     * @param adminGroup The administrators group, used to speed-up creation.
     * @param parentNode The node under which the password is created.
     * @param record The CSVRecord holding the data to import.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the data.
     * @throws IOException Thrown if there is an IOException
     */

    public void importPassword(final User theImporter, final Group adminGroup,
                               final String parentNode, final CSVRecord record)
        throws SQLException, GeneralSecurityException, IOException {

        Iterator<String> values = record.iterator();

        String location = getNextValueFromCSVRecordIterator(values, "Location not specified.");
        String username = getNextValueFromCSVRecordIterator(values, "Username not specified.");
        String password = getNextValueFromCSVRecordIterator(values, "Password not specified.");
        String notes = getNotesFromImport(values);
        int auditing = getAuditLevelFromImport(values);
        boolean recordHistory = getHistoryRecordingFromImport(values);

        Password importedPassword = create(theImporter, adminGroup, username,
                password, location, notes, auditing, recordHistory, Long.MAX_VALUE,
                parentNode, null, false, 0, 0, Password.TYPE_SYSTEM, null);

        User adminUser = UserDAO.getInstance().getAdminUser(adminGroup);
        AccessControl accessControl = GroupAccessControlDAO.getInstance().getGac(adminGroup, importedPassword);

        importCustomFields(adminUser, adminGroup, accessControl, importedPassword, values);

        importAccessControls(adminUser, adminGroup, accessControl, parentNode, importedPassword, values);
    }

    private void importCustomFields(final User adminUser, final Group adminGroup, final AccessControl accessControl,
                                    final Password importedPassword, Iterator<String> values )
        throws GeneralSecurityException, IOException, SQLException  {
        Map<String, String> customFields = new TreeMap<>();
        while (values.hasNext()) {
            String nextToken = values.next().trim();

            if (nextToken.length() < PERMISSION_HEADER_LENGTH
                    || nextToken.charAt(2) != ':') {
                throw new GeneralSecurityException("Incorrect format " + nextToken);
            }

            if (nextToken.startsWith("CF:")) {
                importCustomField(customFields, nextToken.substring(PERMISSION_HEADER_LENGTH));
            } else {
                importPermission(importedPassword, adminUser, adminGroup, nextToken);
            }
        }

        importedPassword.setCustomFields(customFields);
        updateWork(importedPassword, accessControl);
    }

    private void importAccessControls(final User adminUser, final Group adminGroup, final AccessControl accessControl,
                                      final String parentNode, final Password importedPassword,
                                      final Iterator<String> importedPermissions )
            throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
        Map<String,String> userPermissions = new HashMap<>();
        Map<String,String> groupPermissions = new HashMap<>();

        HierarchyNodeDAO.getInstance().
        		getDefaultPermissionsForNodeIncludingInherited(
        				parentNode,
        				userPermissions,
        				groupPermissions
        			);

        updateWithImportedPermissions(userPermissions, groupPermissions, importedPermissions);

        storeImportedUserPermissions(adminGroup, accessControl, importedPassword, userPermissions);
        storeImportedGroupPermissions(adminUser, accessControl, importedPassword, groupPermissions);
    }

    private void updateWithImportedPermissions(Map<String,String> userPermissions, Map<String,String> groupPermissions,
                                               Iterator<String> importedPermissions) {
        UserDAO userDAO = UserDAO.getInstance();
        GroupDAO groupDAO = GroupDAO.getInstance();

        while(importedPermissions.hasNext()) {
            String permission = importedPermissions.next().trim();
            if(permission.isEmpty() || permission.length() < 4) {
                continue;
            }

            String actorName = permission.substring(3);
            try {
                switch (permission.charAt(0)) {
                    case 'U':
                        User user = userDAO.getByName(actorName);
                        importPermission(userPermissions, user.getUserId(), permission);
                        break;
                    case 'G':
                        Group group = groupDAO.getByName(actorName);
                        importPermission(groupPermissions, group.getGroupId(), permission);
                        break;
                    default:
                        Logger.getAnonymousLogger().log(Level.SEVERE, "Unrecognised permission on import : " + permission);
                        break;
                }
            } catch(Exception e) {
                Logger.getAnonymousLogger().log(Level.SEVERE, "Problem importing permission : " +permission);
            }
        }
    }

    private void importPermission(Map<String, String> permissionMap, String id, String permission) {
        switch(permission.charAt(1)) {
            case 'V':
                permissionMap.put(id, AccessControl.READ_PERMISSION);
                break;
            case 'M':
                permissionMap.put(id, AccessControl.MODIFY_PERMISSION);
                break;
        }
    }

    private void storeImportedUserPermissions(final Group adminGroup, final AccessControl accessControl,
                                      final Password importedPassword, final Map<String,String> userPermissions)
            throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
        final UserDAO uDAO = UserDAO.getInstance();
        final UserAccessControlDAO uacDAO = UserAccessControlDAO.getInstance();

        for(Map.Entry<String,String> thisEntry : userPermissions.entrySet()) {
            User user = uDAO.getByIdDecrypted(thisEntry.getKey(), adminGroup);
            UserAccessControl uac = new UserAccessControl();
            uac.setAccessorId(user.getUserId());
            uac.setItemId(importedPassword.getId());
            uac.setReadKey(accessControl.getReadKey());
            if(thisEntry.getValue().equals("2")) {
                uac.setModifyKey(accessControl.getModifyKey());
            }
            uacDAO.write(uac, user);
        }
    }

    private void storeImportedGroupPermissions(final User adminUser, final AccessControl accessControl,
                                              final Password importedPassword, final Map<String,String> groupPermissions)
            throws GeneralSecurityException, UnsupportedEncodingException, SQLException {
        final GroupDAO groupDAO = GroupDAO.getInstance();
        final GroupAccessControlDAO groupAccessControlDAO = GroupAccessControlDAO.getInstance();

        for(Map.Entry<String,String> thisEntry : groupPermissions.entrySet()) {
            Group group = groupDAO.getByIdDecrypted(thisEntry.getKey(), adminUser);
            GroupAccessControl gac = new GroupAccessControl();
            gac.setAccessorId(group.getGroupId());
            gac.setItemId(importedPassword.getId());
            gac.setReadKey(accessControl.getReadKey());
            if(thisEntry.getValue().equals("2")) {
                gac.setModifyKey(accessControl.getModifyKey());
            }
            groupAccessControlDAO.write(group, gac);
        }
    }

    private String getNextValueFromCSVRecordIterator(final Iterator<String> iterator, final String error )
        throws GeneralSecurityException {
        if (!iterator.hasNext()) {
            throw new GeneralSecurityException(error);
        }
        return iterator.next().trim();

    }

    private String getNotesFromImport(Iterator<String> values) {
        if(!values.hasNext()) {
            return "";
        }

        String notes = values.next().trim();
        notes = notes.replaceAll("<br>", "\n");
        notes = notes.replaceAll("<br/>", "\n");
        return notes;
    }

    private int getAuditLevelFromImport(Iterator<String> values)
        throws GeneralSecurityException {
        if (!values.hasNext()) {
            return Password.AUDITING_FULL;
        }

        String audit = values.next().trim().toLowerCase();
        if (audit.length() == 0 || audit.equals("full")) {
            return Password.AUDITING_FULL;
        }
        if (audit.equals("log")) {
            return Password.AUDITING_LOG_ONLY;
        }
        if (audit.equals("none")) {
            return Password.AUDITING_NONE;
        }

        throw new GeneralSecurityException( "Invalid auditing value specified ("+audit+").");
    }

    private boolean getHistoryRecordingFromImport(Iterator<String> values) {
        if(!values.hasNext()) {
            return true;
        }

        String history = values.next().trim().toLowerCase();
        return Boolean.valueOf(history);
    }


    /**
     * Handles the import of a custom field permission.
     *
     * @param customFields The map of custom fields.
     * @param customField The defintiion of the custom field
     */

    private void importCustomField(final Map<String,String> customFields, final String customField) {
    	String fieldName = customField.trim();
    	String fieldValue = "";
    	int equalsIdx = fieldName.indexOf('=');
    	if(equalsIdx != -1) {
    		fieldValue = fieldName.substring(equalsIdx+1);
    		fieldName = fieldName.substring(0, equalsIdx);
    	}
    	customFields.put(fieldName, fieldValue);
    }

    /**
     * Handles the import of an access permission.
     *
     * @param thePassword The password being imported.
     * @param adminUser The administrator user doing the import.
     * @param adminGroup The admin group for permission handling.
     * @param permission The permission being imported.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem encrypting/decrypting the permissions
     * @throws UnsupportedEncodingException Thrown if there is a problem decoding text.
     */

    private void importPermission(final Password thePassword, final User adminUser,
    		final Group adminGroup, final String permission)
    	throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        char permissionType = permission.charAt(1);
        boolean allowModify;
        if (permissionType == 'M') {
            allowModify = true;
        } else if (permissionType == 'V') {
            allowModify = false;
        } else {
        	return;
        }

        // Get the name of the object the permission is for
        String objectName = permission.substring(PERMISSION_HEADER_LENGTH);

        char objectType = permission.charAt(0);
        if (objectType == 'U' || objectType == 'u') {
            User theUser = UserDAO.getInstance().getByName(objectName);
            if (theUser == null) {
                throw new GeneralSecurityException("User " + objectName + " does not exist");
            }
            theUser.decryptAdminAccessKey(adminGroup);
            UserAccessControlDAO.getInstance().create(theUser, thePassword, true, allowModify);
        } else if (objectType == 'G' || objectType == 'g') {
            Group theGroup = GroupDAO.getInstance().getByName(objectName);
            if (theGroup == null) {
                throw new GeneralSecurityException("Group " + objectName+ " does not exist");
            }
            Membership membership =
            	MembershipDAO.getInstance().getMembership(adminUser, theGroup);
            theGroup.updateAccessKey(membership);
            GroupAccessControlDAO.getInstance().create(theGroup, thePassword, true, allowModify);
        }
    }

    /**
     * Get a list of passwords a restriction applies to.
     *
     * @param user The user getting the restriction.
     * @param restrictionId The ID of the restriction to get.
     *
     * @return A List of passwords htat have this restriction associated with them.
     *
     * @throws SQLException
     *             Thrown if there is problem talking to the database.
     */

    public List<Password> getPasswordsRestrictionAppliesTo(final User user, final String restrictionId)
            throws SQLException, GeneralSecurityException, IOException {
        return getMultiple(USE_CHECK_SQL, restrictionId);
    }

    /**
     * Method to determine if there are any expiring passwords accessible
     * by this user.
     *
     * @param user The user accessing the passwords.
     *
     * @return true if the password is expiring, false if not.
     */

    public boolean hasExpiringPasswords(final User user)
    	throws SQLException, GeneralSecurityException, UnsupportedEncodingException {

    	Calendar expiryCal = Calendar.getInstance();
        String warningPeriod = ConfigurationDAO.getValue(ConfigurationOption.DAYS_BEFORE_EXPIRY_TO_WARN);
        if (warningPeriod != null && warningPeriod.length() > 0) {
            try {
                expiryCal.add(Calendar.DAY_OF_MONTH, Integer.parseInt(warningPeriod));
            } catch (NumberFormatException ex) {
            	expiryCal.add(Calendar.DAY_OF_MONTH, DEFAULT_PASSWORD_EXPIRY_WARNING_DAYS);
            	ConfigurationDAO.getInstance().delete(ConfigurationOption.DAYS_BEFORE_EXPIRY_TO_WARN);
            }
        } else {
            expiryCal.add(Calendar.DAY_OF_MONTH, DEFAULT_PASSWORD_EXPIRY_WARNING_DAYS);
        }
        long expiryWarningDate = expiryCal.getTimeInMillis();

        Statement stmt = BOMFactory.getCurrentConntection().createStatement();
        try {
        	ResultSet rs = stmt.executeQuery(GET_EXPIRY_DETAILS_SQL);
        	try {
	        	while(rs.next()) {
	        		String id = rs.getString(1);
	        		byte[] data = rs.getBytes(2);
	        		if( rs.wasNull() ) {
	        			continue;
	        		}
	        		AccessControl ac = AccessControlDAO.getInstance().getReadAccessControl(user, id);
	        		if(ac == null) {
	        			continue;
	        		}

	        		try {
	        			Password password = new Password(id, data, ac);
		        		if( password.getExpiry() < expiryWarningDate) {
		        			return true;
		        		}
	        		} catch(IOException ioe) {
	        			// Do nothing
	        		}
	        	}
        	} finally {
            	DatabaseConnectionUtils.close(rs);
        	}
        } finally {
        	DatabaseConnectionUtils.close(stmt);
        }

        return false;
    }

    /**
     * Performs an action on all passwords stored in the database.
     *
     * @param user The user performing the action.
     * @param action The object which will act on each password.
     *
     * @throws Exception Any exception can be thrown during the processing of passwords.
     */

    public void processAllPasswords(final User user, final PasswordAction action) throws Exception {
        List<String> processedIds = new ArrayList<>();
        if (user.isAdministrator()) {
            processAllPasswordsWork(
                    user,
                    action,
                    GET_ALL_PASSWORDS_FOR_ACTION_BY_USER_EVEN_IF_DISABLED_SQL,
                    processedIds
                );
            processAllPasswordsWork(
                    user,
                    action,
                    GET_ALL_PASSWORDS_FOR_ACTION_BY_GROUP_EVEN_IF_DISABLED_SQL,
                    processedIds
                );
        } else {
            processAllPasswordsWork(
                    user,
                    action,
                    GET_ALL_PASSWORDS_FOR_ACTION_BY_USER_SQL,
                    processedIds
                );
            processAllPasswordsWork(
                    user,
                    action,
                    GET_ALL_PASSWORDS_FOR_ACTION_BY_GROUP_SQL,
                    processedIds
                );
        }
    }

    /**
     * Performs an action on all passwords stored in the database.
     *
     * @param user The user performing the action.
     * @param action The object which will act on each password.
     * @param sql The SQL to use to get the passwords.
     * @param processedIds The List of IDs which have been processed
     *
     * @throws Exception Any exception can be thrown during the processing of passwords.
     */

    public void processAllPasswordsWork(final User user,
    		final PasswordAction action, final String sql,
    		final List<String> processedIds)
        throws Exception {
        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql);
        try {
            ps.setString(1, user.getUserId());

            ResultSet rs = ps.executeQuery();
            try {
            	AccessControlDAO acDAO = AccessControlDAO.getInstance();
		        while (rs.next()) {
		            final String id = rs.getString(1);
		            if (processedIds.contains(id)) {
		            	continue;
		            }
		            final AccessControl ac = acDAO.getAccessControl(user, id);
		            if( ac == null ) {
		            	continue;
		            }
		            final Password thisPassword = new Password(id, rs.getBytes(2), ac);
	                action.process(null, thisPassword);
	                processedIds.add(id);
		        }
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Gets the list of passwords this user has access to that are expiring or
     * have expired.
     *
     * @param user The user getting the list of expired passwords.
     *
     * @return The expiring passwords the user has access to.
     *
     * @throws Exception Thrown if there is an error during the search.
     */

    public ExpiringAccessiblePasswords getExpiringPasswords(final User user)
            throws Exception {
        ExpiringAccessiblePasswordsAction expiryTester = new ExpiringAccessiblePasswordsAction(user);
        processAllPasswords(user, expiryTester);
        return expiryTester;
    }

    /**
     * Get the list of email addresses for users who have access to a
     * password.
     *
     * @param  password The password to get the list of users with access.
     *
     * @return The Set of email addresses.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    public final Set<String> getEmailsOfUsersWithAccess(final Password password)
        throws SQLException {
        Set<String> emailAddresses = new HashSet<>();

        getEmailAddressesWork(password, EMAILS_WITH_ACCESS_VIA_UAC, emailAddresses);
        getEmailAddressesWork(password, EMAILS_WITH_ACCESS_VIA_GAC, emailAddresses);

        return emailAddresses;
    }

    /**
     * Runs the SQL responsible for getting a set of email addresses for users with access
     * to a password.
     *
     * @param password The password to get the list for.
     * @param sql The SQL to execute to get the user list.
     * @param emailAddresses The Set containing email addresses.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    private void getEmailAddressesWork(final Password password, final String sql,
            final Set<String> emailAddresses)
        throws SQLException {
        PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql);
        try {
            ps.setString(1, password.getId());
            ResultSet rs = ps.executeQuery();
            try {
	            while (rs.next()) {
	                String emailAddress = rs.getString(1);
	                if (emailAddress != null) {
	                    emailAddresses.add(emailAddress);
	                }
	            }
            } finally {
                DatabaseConnectionUtils.close(rs);
            }
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Gets the id and X@Y form of the all passwords available via
     * the admnin group GAC.
     *
     * @param adminGroup The admin group.
     *
     * @return A List of PasswordBase.Summary objects.
     * @throws UnsupportedEncodingException
     */

    public final Set<PasswordSummary> getSummaryForAll(final Group adminGroup)
    	throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
    	TreeSet<PasswordSummary> summaryList = new TreeSet<>();

    	Statement stmt = BOMFactory.getCurrentConntection().createStatement();
    	try {
    		ResultSet rs = stmt.executeQuery(GET_ALL_SUMMARY_DETAILS);
    		try {
	    		while( rs.next() ) {
	    			GroupAccessControl gac = new GroupAccessControl(rs, 3, adminGroup);

	    			final String id = rs.getString(1);

	    			try {
		    			PasswordBase password = PasswordUtils.decrypt(gac, rs.getBytes(2));
		    			summaryList.add( new PasswordSummary(id, password.getUsername()+"@"+password.getLocation()));
	    			} catch(Exception ex) {
	    				Logger.getAnonymousLogger().log(Level.SEVERE, "Problem decrypting password "+id, ex);
	    			}
	    		}
        	} finally {
        		DatabaseConnectionUtils.close(rs);
        	}
    	} finally {
    		DatabaseConnectionUtils.close(stmt);
    	}

    	return summaryList;
    }

    /**
     * Returns a list of the password IDs which match he given search criteria.
     *
     * @param user The user the search is being performed for.
     * @param searchUsername The username being searched for.
     * @param searchLocation The location being searched for.
     *
     * @return The list of Ids.
     */
	public Set<String> performRawAPISearch(User user, String searchUsername, String searchLocation)
		throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
		Set<String> ids = new TreeSet<>();
        String locationId = LocationDAO.getInstance().getId(searchLocation);

		performRawAPIUserSearch(
                user,
                searchUsername,
                locationId,
                ids
            );
		performRawAPIGroupSearch(
                user,
                searchUsername,
                locationId,
                ids
            );
		return ids;
	}

	/**
	 * Get all of the passwords in a location.
	 *
	 * @param user The user fetching the list.
	 * @param locationId The ID of the location to get the passwords for.
	 * @param passwords The Set to add the Passwords to.
     *
	 * @throws SQLException
	 * @throws IOException
	 */
	public void getAllForLocation(final User user, final String locationId, final Set<Password> passwords)
			throws SQLException, GeneralSecurityException, IOException {
		PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_ALL_FOR_LOCATION_SQL);
		try {
			ps.setString(1, locationId);
			ResultSet rs = ps.executeQuery();
			try {
				AccessControlDAO acDAO = AccessControlDAO.getInstance();
				while(rs.next()) {
		            final String id = rs.getString(1);
		            final AccessControl ac = acDAO.getAccessControl(user, id);
		            if( ac == null ) {
		            	continue;
		            }
		            final Password thisPassword = new Password(id, rs.getBytes(2), ac);
		            passwords.add(thisPassword);
				}
			} finally {
				DatabaseConnectionUtils.close(rs);
			}
		} finally {
			DatabaseConnectionUtils.close(ps);
		}
	}


    /**
     * Returns a list of the password IDs which match he given search criteria.
     *
     * @param user The user the search is being performed for.
     * @param searchUsername The username being searched for.
     * @param searchLocation The location being searched for.
     * @param ids The list of ids which match.
     */
	public void performRawAPIUserSearch(final User user, final String searchUsername,
			final String searchLocation, final Set<String> ids)
		throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
		PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(SEARCH_ALL_PASSWORDS_FOR_LOCATIONS_BY_USER_SQL);
		try {
			ps.setString(1, user.getUserId());
			ps.setString(2, searchLocation);
			ResultSet rs = ps.executeQuery();
			try {
				while(rs.next()) {
					final String passwordId = rs.getString(1);
					byte[] data = rs.getBytes(2);

					UserAccessControl ac = UserAccessControlDAO.getInstance().getUac(user, passwordId);

					Password password = new Password();
					try {
						PasswordUtils.decrypt(password, ac, data);
						if( password.getUsername().equals(searchUsername) ) {
							ids.add(passwordId);
						}
					} catch(IOException ioe) {
						// Do nothing on a fail
					}
				}
			} finally {
				DatabaseConnectionUtils.close(rs);
			}
		} finally {
			DatabaseConnectionUtils.close(ps);
		}
	}

    /**
     * Returns a list of the password IDs which match he given search criteria.
     *
     * @param user The user the search is being performed for.
     * @param searchUsername The username being searched for.
     * @param searchLocation The location being searched for.
     * @param ids The list of ids which match.
     */
	public void performRawAPIGroupSearch(final User user, final String searchUsername,
			final String searchLocation, final Set<String> ids)
		throws SQLException, UnsupportedEncodingException, GeneralSecurityException {
		PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(SEARCH_ALL_PASSWORDS_FOR_LOCATIONS_BY_GROUP_SQL);
		try {
			ps.setString(1, user.getUserId());
			ps.setString(2, searchLocation);
			ResultSet rs = ps.executeQuery();
			try {
				while(rs.next()) {
					final String passwordId = rs.getString(1);
					byte[] data = rs.getBytes(2);
					String groupId = rs.getString(3);

					Group group = GroupDAO.getInstance().getByIdDecrypted(groupId, user);
					GroupAccessControl ac = GroupAccessControlDAO.getInstance().getGac(user, group, passwordId);

					Password password = new Password();
					try {
						PasswordUtils.decrypt(password, ac, data);
						if( password.getUsername().equals(searchUsername) ) {
							ids.add(passwordId);
						}
					} catch(IOException ioe) {
						// Do nothing on a fail
					}
				}
			} finally {
				DatabaseConnectionUtils.close(rs);
			}
		} finally {
			DatabaseConnectionUtils.close(ps);
		}
	}

    //------------------------

    private static final class InstanceHolder {
    	static final PasswordDAO INSTANCE = new PasswordDAO();
    }

    public static PasswordDAO getInstance() {
		return InstanceHolder.INSTANCE;
    }

}
