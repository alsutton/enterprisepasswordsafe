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

import com.enterprisepasswordsafe.database.actions.password.ExpiringAccessiblePasswordsAction;
import com.enterprisepasswordsafe.database.derived.ExpiringAccessiblePasswords;
import com.enterprisepasswordsafe.database.derived.ImmutableExpiringAccessiblePasswords;
import com.enterprisepasswordsafe.engine.accesscontrol.AccessControl;
import com.enterprisepasswordsafe.engine.accesscontrol.GroupAccessControl;
import com.enterprisepasswordsafe.engine.accesscontrol.PasswordPermission;
import com.enterprisepasswordsafe.engine.accesscontrol.UserAccessControl;
import com.enterprisepasswordsafe.engine.passwords.AuditingLevel;
import com.enterprisepasswordsafe.engine.passwords.PasswordPermissionApplier;
import com.enterprisepasswordsafe.engine.utils.PasswordUtils;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.*;

public final class PasswordDAO
        extends PasswordStoreManipulator  {

    private static final int DEFAULT_PASSWORD_EXPIRY_WARNING_DAYS = 7;

    private static final String USE_CHECK_SQL =
    		"SELECT " + PASSWORD_FIELDS + " FROM passwords pass WHERE pass.restriction_id = ?";

    private static final String GET_BY_ID_SQL = "SELECT " + PASSWORD_FIELDS
            + "  FROM passwords pass" + " WHERE pass.password_id = ? "
            + "   AND (pass.enabled is null OR pass.enabled = 'Y')";

    private static final String SEARCH_ALL_PASSWORDS_FOR_LOCATIONS_BY_USER_SQL =
            "SELECT " + PASSWORD_FIELDS + " FROM passwords pass, user_access_control uac "
            + " WHERE uac.user_id = ? AND uac.item_id = pass.password_id"
            + "  AND (pass.enabled is null OR pass.enabled = 'Y') AND pass.location_id = ? ";

    private static final String SEARCH_ALL_PASSWORDS_FOR_LOCATIONS_BY_GROUP_SQL =
            "SELECT " + PASSWORD_FIELDS + " FROM passwords pass, group_access_control  gac, membership mem "
            + " WHERE mem.user_id  = ? AND mem.group_id    = gac.group_id AND gac.item_id = pass.password_id "
            + " AND (pass.enabled is null OR pass.enabled = 'Y') AND pass.location_id = ? ";

    private static final String EMAILS_WITH_ACCESS_VIA_UAC = "SELECT users.email "
            + "  FROM application_users users, user_access_control uac "
            + " WHERE uac.item_id = ? AND uac.rkey IS NOT NULL AND uac.user_id = users.user_id AND users.disabled is null ";

    private static final String EMAILS_WITH_ACCESS_VIA_GAC = "SELECT users.email "
            + "  FROM application_users users, group_access_control gac, membership mem, groups grp "
            + " WHERE gac.item_id = ? AND gac.rkey IS NOT NULL AND gac.group_id = grp.group_id "
            + "  AND  grp.status = " + Group.STATUS_ENABLED + " AND gac.group_id = mem.group_id "
            + "  AND mem.user_id = users.user_id AND users.disabled is null ";

    private static final String WRITE_PASSWORD_SQL =
            "INSERT INTO passwords(password_id, enabled, audited, history_stored, restriction_id, ra_enabled, "
            + "		ra_approvers, ra_blockers, ptype, location_id, password_data  )"
            + " VALUES ( ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ? )";

    private static final String GET_EXPIRY_DETAILS_SQL =
    	"SELECT password_id, password_data FROM passwords";

	private PasswordDAO( ) {
		super(GET_BY_ID_SQL);
	}

	public UserAccessControl storeNewPassword(final Password thePassword, final User creator )
		throws SQLException, GeneralSecurityException, IOException {
        Group adminGroup = GroupDAO.getInstance().getAdminGroup(creator);
        if (adminGroup == null) {
            throw new GeneralSecurityException("You can not create new passwords.");
        }

        GroupAccessControlDAO gacDAO = GroupAccessControlDAO.getInstance();
    	GroupAccessControl gac = gacDAO.create(adminGroup, thePassword, PasswordPermission.MODIFY, false);

        write(thePassword, gac);

        gacDAO.write(adminGroup, gac);
        return UserAccessControlDAO.getInstance().create(creator, thePassword, PasswordPermission.MODIFY);
	}

	public Password getById(final User user, final String id)
            throws SQLException, IOException, GeneralSecurityException {
        AccessControl ac = AccessControlDAO.getInstance().getReadAccessControl(user, id);
        if( ac == null )
        	return null;

        return getById(id, ac);
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
     * @throws IOException Thrown if there is an IOException
     */

    public Password create(final User theCreator, final Group adminGroup,
                           final String username, final String password, final String location,
                           final String notes, final AuditingLevel audit, final boolean history,
                           final long expiry, final String parentNode, final String restrictionId,
                           final boolean raEnabled, final int raApprovers, final int raBlockers,
                           final int type, Map<String,String> customFields)
            throws SQLException, GeneralSecurityException, IOException {
        Password newPassword = new Password(username, password, location, notes, AuditingLevel.FULL, history, expiry);
        newPassword.setPasswordType(type);
        newPassword.setRestrictionId(restrictionId);
        newPassword.setRaEnabled(raEnabled);
        newPassword.setRaBlockers(raBlockers);
        newPassword.setRaApprovers(raApprovers);
        newPassword.setAuditLevel(audit);
        newPassword.setCustomFields(customFields);

        UserAccessControl newUac =
        		UserAccessControlDAO.getInstance().create(theCreator, newPassword, PasswordPermission.MODIFY, false);

        write(newPassword, newUac);

        UserAccessControlDAO.getInstance().write(theCreator, newUac);

        HierarchyNode node = new HierarchyNode(newPassword.getId(), parentNode, HierarchyNode.OBJECT_NODE);
        HierarchyNodeDAO.getInstance().store(node);

        if( adminGroup != null ) {
            GroupAccessControlDAO.getInstance().create(adminGroup, newPassword, PasswordPermission.MODIFY);
            new PasswordPermissionApplier().setDefaultPermissions(newPassword, parentNode, adminGroup);
	        TamperproofEventLogDAO.getInstance().create( TamperproofEventLog.LOG_LEVEL_OBJECT_MANIPULATION,
                theCreator, newPassword, "Created the password.", newPassword.getAuditLevel().shouldTriggerEmail());
        }

        return newPassword;
    }

    public void write(final Password password, final Group group)
            throws SQLException, GeneralSecurityException, IOException {
    	GroupAccessControl gac = GroupAccessControlDAO.getInstance().create(group, password, PasswordPermission.MODIFY);
        GroupAccessControlDAO.getInstance().write(group, gac);

        write(password, gac);
    }

    public void write(final Password password, final AccessControl ac)
        throws SQLException, GeneralSecurityException, IOException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(WRITE_PASSWORD_SQL)) {
            ps.setString(1, password.getId());
            ps.setString(2, password.isEnabled() ? "Y" : "N");
            ps.setString(3, password.getAuditLevel().toString());
            ps.setString(4, password.isHistoryStored() ? "Y" : "N");
            ps.setString(5, password.getRestrictionId());
            ps.setString(6, password.isRaEnabled() ? "Y" : "N");
            ps.setInt(7, password.getRaApprovers());
            ps.setInt(8, password.getRaBlockers());
            ps.setInt(9, password.getPasswordType());
            ps.setString(10, LocationDAO.getInstance().getId(password.getLocation()));
            ps.setBytes(11, PasswordUtils.encrypt(password, ac));
            ps.executeUpdate();

            // Write the password with the data encrypted
            if (password.isHistoryStored()) {
            	HistoricalPasswordDAO.getInstance().writeHistoryEntry(password, ac);
            }
        }
    }

    public List<Password> getPasswordsRestrictionAppliesTo(final String restrictionId)
            throws SQLException {
        return getMultiple(USE_CHECK_SQL, restrictionId);
    }

    public boolean hasExpiringPasswords(final User user)
            throws SQLException, GeneralSecurityException, IOException {
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

        for(Password password : getMultiple(user, GET_EXPIRY_DETAILS_SQL)) {
            if( password.getExpiry() < expiryWarningDate) {
                return true;
            }
        }

        return false;
    }

    public ExpiringAccessiblePasswords getExpiringPasswords(final User user)
            throws Exception {
        ExpiringAccessiblePasswordsAction expiryTester = new ExpiringAccessiblePasswordsAction(user);
        new PasswordProcessor().processAllPasswords(user, expiryTester);
        return ImmutableExpiringAccessiblePasswords.builder()
                .expired(expiryTester.getExpired())
                .expiring(expiryTester.getExpiring())
                .build();
    }

    public final Set<String> getEmailsOfUsersWithAccess(final Password password)
        throws SQLException {
        Set<String> emailAddresses = new HashSet<>();

        getEmailAddressesWork(password, EMAILS_WITH_ACCESS_VIA_UAC, emailAddresses);
        getEmailAddressesWork(password, EMAILS_WITH_ACCESS_VIA_GAC, emailAddresses);

        return emailAddresses;
    }

    private void getEmailAddressesWork(final Password password, final String sql,
            final Set<String> emailAddresses)
        throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(sql)) {
            ps.setString(1, password.getId());
            try(ResultSet rs = ps.executeQuery()) {
	            while (rs.next()) {
	                String emailAddress = rs.getString(1);
	                if (emailAddress != null) {
	                    emailAddresses.add(emailAddress);
	                }
	            }
            }
        }
    }

	public Set<String> performRawAPISearch(User user, String searchUsername, String searchLocation)
            throws SQLException, IOException, GeneralSecurityException {
		Set<String> ids = new TreeSet<>();
		if (searchUsername == null) {
		    return ids;
        }

        String locationId = LocationDAO.getInstance().getId(searchLocation);

		performRawAPIUserSearch(user, searchUsername, locationId, ids);
		performRawAPIGroupSearch(user, searchUsername, locationId, ids);
		return ids;
	}

	private void performRawAPIUserSearch(final User user, final String searchUsername,
			final String searchLocation, final Set<String> ids)
            throws SQLException, IOException, GeneralSecurityException {
	    for(Password password: getMultiple(SEARCH_ALL_PASSWORDS_FOR_LOCATIONS_BY_USER_SQL, user.getId(), searchLocation)) {
            addIdIfMatches(ids, password, UserAccessControlDAO.getInstance().get(user, password.getId()), searchUsername);
        }
	}

	private void performRawAPIGroupSearch(final User user, final String searchUsername,
			final String searchLocation, final Set<String> ids)
            throws SQLException, IOException, GeneralSecurityException {
        for(Password password: getMultiple(SEARCH_ALL_PASSWORDS_FOR_LOCATIONS_BY_GROUP_SQL, user.getId(), searchLocation)) {
            addIdIfMatches(ids, password, GroupAccessControlDAO.getInstance().get(user, password.getId()), searchUsername);
        }
	}

	private void addIdIfMatches(Set<String> ids, Password password, AccessControl ac, String searchUsername)
            throws GeneralSecurityException, IOException, SQLException {
        if(ac == null) {
            return;
        }
        password.decryptPasswordProperties(ac);
        if (searchUsername.equals(password.getUsername())) {
            ids.add(password.getId());
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
