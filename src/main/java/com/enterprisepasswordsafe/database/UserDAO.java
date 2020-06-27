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

import com.enterprisepasswordsafe.database.derived.UserSummary;
import com.enterprisepasswordsafe.engine.jaas.EPSJAASConfiguration;
import com.enterprisepasswordsafe.engine.jaas.WebLoginCallbackHandler;
import com.enterprisepasswordsafe.engine.users.UserAccessKeyEncryptionHandler;
import com.enterprisepasswordsafe.engine.users.UserClassifier;
import com.enterprisepasswordsafe.engine.users.UserPasswordEncryptionHandler;
import com.enterprisepasswordsafe.engine.utils.KeyUtils;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Calendar;
import java.util.List;

/**
 * Data access object for the user objects.
 */
public final class UserDAO extends StoredObjectManipulator<User> {

    public static final String USER_FIELDS = "appusers.user_id, "
            + "appusers.user_name, appusers.user_pass_b, appusers.email, appusers.full_name, "
            + "appusers.akey, appusers.aakey, appusers.last_login_l, "
            + "appusers.auth_source, appusers.disabled, appusers.pwd_last_changed_l";


    /**
     * The SQL to get a count of the number of enabled users.
     */

    static final String GET_COUNT_SQL = "SELECT count(*) FROM application_users WHERE disabled is null OR disabled = 'N'";

    /**
     * The SQL to get a particular user by their ID.
     */

    private static final String GET_BY_ID_SQL =
            "SELECT " + USER_FIELDS + " FROM application_users appusers WHERE appusers.user_id = ? ";

    /**
     * The SQL statement to get a category.
     */

    private static final String GET_BY_NAME_SQL =
            "SELECT " + USER_FIELDS + " FROM application_users appusers WHERE appusers.user_name = ?"
            + "   AND (appusers.disabled is null OR appusers.disabled = 'N')";

    /**
     * The SQL statement to get all users.
     */

    private static final String GET_ENABLED_USERS_SQL =
            "SELECT " + USER_FIELDS + " FROM application_users appusers WHERE appusers.user_id <> '0' "
            + "   AND (appusers.disabled is null OR appusers.disabled = 'N')"
            + " ORDER BY appusers.user_name ASC";

    /**
     * The SQL statement to get all users even if they are disabled.
     */

    private static final String GET_ALL_USERS_SQL =
            "SELECT " + USER_FIELDS + " FROM application_users appusers "
            + " WHERE appusers.user_id <> '"+UserClassifier.ADMIN_USER_ID+"' AND appusers.disabled <> 'D'"
            + " ORDER BY appusers.user_name ASC";

    /**
     * The SQL write a users details to the database.
     */

    private static final String WRITE_SQL =
              "INSERT INTO application_users( user_id, user_name, user_pass_b, full_name, " +
              " email, last_login_l, disabled, akey, aakey ) VALUES( ?, ?, ?, ?, ?, ?, ?, ?, ? )";

    /**
     * The SQL write a users details to the database.
     */

    private static final String UPDATE_SQL =
              "UPDATE	application_users" +
              "   SET	user_name = ?, user_pass_b = ?, full_name = ?, email = ?, " +
              "			last_login_l = ?, disabled = ?, pwd_last_changed_l = ?, auth_source = ? "+
              " WHERE	user_id = ?";

    private static final String GROUP_MEMBER_LIST_SQL =
            "SELECT " + USER_FIELDS + " FROM application_users appusers, membership m "
                    + " WHERE m.group_id = ? AND m.user_id = appusers.user_id AND appusers.user_id <> '0' "
                    + " AND (appusers.disabled is null OR appusers.disabled = 'N') ORDER BY appusers.user_name ASC";

    private static final String GET_LOGIN_ATTEMPTS_SQL =
            "SELECT	appusers.login_attempts FROM application_users appusers WHERE appusers.user_id = ? ";


    private static final String SET_LOGIN_FAILURE_COUNT =
            "UPDATE application_users SET login_attempts = ? WHERE user_id = ? ";

    /**
     * The SQL to see if a user is member of a particular group.
     */

    private static final String DELETE_USER_SQL = "UPDATE application_users SET DISABLED = 'D' WHERE user_id = ? ";

    /**
     * The SQL to delete a users memberships.
     */

    private static final String DELETE_USER_MEMBERSHIPS = "DELETE FROM membership WHERE user_id = ?";

    /**
     * The SQL to delete a users memberships.
     */

    private static final String DELETE_UACS = "DELETE FROM user_access_control WHERE user_id = ?";

    /**
     * The SQL to delete a users memberships.
     */

    private static final String DELETE_UARS = "DELETE FROM hierarchy_access_control WHERE user_id = ?";

    /**
     * Update the admin access key for a user
     */

    private static final String UPDATE_ADMIN_ACCESS_KEY = "UPDATE application_users SET aakey = ? WHERE user_id = ?";

    private static final String UPDATE_LOGIN_PASSWORD_SQL =
            "UPDATE application_users SET user_pass_b = ?, pwd_last_changed_l = ?, akey = ? WHERE user_id = ?";

    /**
     * The array of SQL statements run to delete a user.
     */

    private static final String[] DELETE_SQL_STATEMENTS = {
            DELETE_UACS, DELETE_UARS, DELETE_USER_MEMBERSHIPS, DELETE_USER_SQL
    };

    private final UserClassifier userClassifier = new UserClassifier();

	/**
	 * Private constructor to prevent instantiation
	 */

	private UserDAO() {
	    super(GET_BY_ID_SQL, GET_BY_NAME_SQL, GET_COUNT_SQL);
	}

	User newInstance(ResultSet rs)
            throws SQLException {
	    return new User(rs, 1);
    }

    /**
     * Gets the administrator user using the admin group.
     *
     * @param adminGroup group The admin group.
     *
     * @return The admin user.
     */

    public User getAdminUser(final Group adminGroup)
    	throws SQLException, GeneralSecurityException {
    	if(adminGroup == null || !adminGroup.getGroupId().equals(Group.ADMIN_GROUP_ID)) {
    		throw new GeneralSecurityException("Attempt to get admin user with non-admin group");
    	}

        User adminUser = UserDAO.getInstance().getByName("admin");
        adminUser.decryptAdminAccessKey(adminGroup);

        return adminUser;
    }

    /**
     * Gets the administrator user using the admin group.
     *
     * @param theUser the user via which we can fetch the admin group, then the admin user.
     *
     * @return The admin user.
     */

    public User getAdminUserForUser(final User theUser)
    	throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
    	Group adminGroup = GroupDAO.getInstance().getAdminGroup(theUser);
    	return getAdminUser(adminGroup);
    }

    /**
     * Mark a user as deleted.
     *
     * @param user The user to mark as deleted.
     */

    public void delete( final User user )
            throws SQLException {
        String userId = user.getId();
        for(String statement : DELETE_SQL_STATEMENTS) {
            try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(statement)) {
                ps.setString(1, userId);
                ps.executeUpdate();
            }
        }
    }

    public void increaseFailedLogins( User user )
        throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
    	int loginAttempts = getFailedLoginAttempts(user)+1;
    	setFailedLogins(user, loginAttempts);

        String maxAttempts = ConfigurationDAO.getValue(ConfigurationOption.LOGIN_ATTEMPTS);
        int maxAttemptsInt = Integer.parseInt(maxAttempts);
        if( loginAttempts >= maxAttemptsInt ) {
        	TamperproofEventLogDAO.getInstance().create(TamperproofEventLog.LOG_LEVEL_USER_MANIPULATION,
                    user, "The user "+ user.getUserName() +
                    " has been disabled to due too many failed login attempts ("+loginAttempts+").", false );
            user.setEnabled(false);
            update(user);
        }
    }

    /**
     * Update the users login password.
     *
     * @param theUser The user being updated.
     * @param newPassword The new password.
     */

    public void updatePassword(User theUser, String newPassword )
    	throws UnsupportedEncodingException, SQLException, GeneralSecurityException {

    	boolean committed = false;

    	Connection connection = BOMFactory.getCurrentConntection();
    	boolean autoCommit = connection.getAutoCommit();
    	connection.setAutoCommit(false);
    	try {

	    	if( userClassifier.isMasterAdmin(theUser) ) {
	    		Group adminGroup = GroupDAO.getInstance().getAdminGroup(theUser);

	            KeyGenerator kgen = KeyGenerator.getInstance(User.USER_KEY_ALGORITHM);
	            kgen.init(User.USER_KEY_SIZE);
	            SecretKey accessKey = kgen.generateKey();

	            Encrypter newEncrypter = new UserAccessKeyEncryptionHandler(accessKey);
	            UserAccessControlDAO.getInstance().updateEncryptionOnKeys(theUser, newEncrypter);
	            MembershipDAO.getInstance().updateEncryptionOnKeys(theUser, newEncrypter);

	            theUser.setAccessKey(accessKey);
	            updateAdminKey(theUser, adminGroup);
	    	}

	    	updateLoginPassword(theUser, newPassword);
	    	connection.commit();
	    	committed = true;
    	} finally {
    		if(!committed) {
        		connection.rollback();
    		}
    		connection.setAutoCommit(autoCommit);
    	}
    }

    /**
     * Update the admin key for a user.
     */

    private void updateAdminKey(final User user, final Group adminGroup) throws SQLException, GeneralSecurityException {
        try (PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(UPDATE_ADMIN_ACCESS_KEY)) {
        	final byte[] encryptedKey = KeyUtils.encryptKey(user.getAccessKey(), adminGroup.getKeyEncrypter());
        	ps.setBytes(1, encryptedKey);
        	ps.setString(2, user.getId());
        	ps.execute();
        }
    }

    public User createUser(final User creatingUser, final UserSummary newUser, final String password,
                           final String email)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        if(password == null || password.isEmpty()) {
            throw new GeneralSecurityException("The user must have a password");
        }

        if (getByName(newUser.getName()) != null) {
            throw new GeneralSecurityException("The user already exists");
        }

        // Get the admin group from the creating user
        Group adminGroup = GroupDAO.getInstance().getAdminGroup(creatingUser);

        // Create the user object
        User createdUser = new User(newUser.getName(), password, newUser.getFullName(), email);
        write(createdUser, adminGroup, password);

        // Write to the database and log creation
        setFailedLogins(createdUser, 0);
        TamperproofEventLogDAO.getInstance().create( TamperproofEventLog.LOG_LEVEL_USER_MANIPULATION,
                creatingUser, "Created the user {user:"+ createdUser.getId() + "}", true);

        Group allUsersGroup = GroupDAO.getInstance().getById(Group.ALL_USERS_GROUP_ID);
        if( allUsersGroup != null ) {
        	MembershipDAO mDAO = MembershipDAO.getInstance();
	        Membership theMembership = mDAO.getMembership(creatingUser, allUsersGroup);
	        allUsersGroup.updateAccessKey(theMembership);
	        mDAO.create(createdUser, allUsersGroup);
        }

        String defaultSource = ConfigurationDAO.getValue(ConfigurationOption.DEFAULT_AUTHENTICATION_SOURCE_ID);
        createdUser.setAuthSource(defaultSource);
        update(createdUser);

        return createdUser;
    }


    public int getFailedLoginAttempts(User user)
            throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_LOGIN_ATTEMPTS_SQL)) {
            ps.setString(1, user.getId());
            try(ResultSet rs = ps.executeQuery()) {
                if (!rs.next()) {
                    return 0;
                }

                int fetchedAttempts = rs.getInt(1);
                return rs.wasNull() ? 0 : fetchedAttempts;
            }
        }
    }

    public void setFailedLogins(User user, int count)
            throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(SET_LOGIN_FAILURE_COUNT)) {
            ps.setInt(1, count);
            ps.setString(2, user.getId());
            ps.executeUpdate();
        }
    }

    /**
     * Writes a user to the database.
     *
     * @param theUser The user to write.
     * @param adminGroup The admin group, used to encrypt the access key for admin access.
     * @param initialPassword The initial password, used to encrypt the access key for the users access.
     */

    public void write(final User theUser, final Group adminGroup, final String initialPassword)
        throws SQLException, GeneralSecurityException {
        try (PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement( WRITE_SQL)) {
            ps.setString(1, theUser.getId());
            ps.setString(2, theUser.getUserName());
            ps.setBytes (3, theUser.getPassword());
            ps.setString(4, theUser.getFullName());
            ps.setString(5, theUser.getEmail());
            ps.setLong  (6, theUser.getLastLogin());
            ps.setString(7, "N");

            final byte[] keyData = theUser.getAccessKey().getEncoded();
            UserPasswordEncryptionHandler encryptionHandler = new UserPasswordEncryptionHandler(initialPassword);
            ps.setBytes (8, encryptionHandler.encrypt(keyData));
            ps.setBytes (9, adminGroup.encrypt(keyData));
            ps.executeUpdate();
        }
    }

    /**
     * Update a user in the database.
     *
     * @param theUser The user to update.
     */

    public void update(User theUser)
        throws SQLException {
        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement( UPDATE_SQL)) {
            ps.setString(1, theUser.getUserName());
            ps.setBytes (2, theUser.getPassword());
            ps.setString(3, theUser.getFullName());
            ps.setString(4, theUser.getEmail());
            ps.setLong  (5, theUser.getLastLogin());
            ps.setString(6, theUser.isEnabled() ? "N" : "Y");
            ps.setLong  (7, theUser.getPasswordLastChanged());
            ps.setString(8, theUser.getAuthSource());
            ps.setString(9, theUser.getId());
            ps.executeUpdate();
        }
    }

    /**
     * Gets a list of all users.
     *
     * @return A List of all users in the system.
     */

    public List<User> getAll()
        throws SQLException {
        return getMultiple(GET_ALL_USERS_SQL);
    }

    /**
     * Gets a list of all enabled users.
     *
     * @return A List of all enabled users in the system.
     */

    public List<User> getEnabledUsers()
        throws SQLException {
        return getMultiple(GET_ENABLED_USERS_SQL);
    }

    /**
     * Get a user and decrypt it's access key.
     *
     * @param userId The ID of the user to fetch.
     * @param adminGroup The admin group to decrypt the users access key with.
     *
     * @return The decrypted user.
     */

	public User getByIdDecrypted(String userId, Group adminGroup)
		throws SQLException, GeneralSecurityException {
		User encryptedUser = getById(userId);
		if(encryptedUser == null) {
			return null;
		}
		encryptedUser.decryptAdminAccessKey(adminGroup);
		return encryptedUser;
	}

    /**
     * Authenticates the user.
     *
     * @param theUser The user to authenticate
     * @param loginPassword The password the user has logged in with.
     */

    public final void authenticateUser(final User theUser, final String loginPassword)
    	throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        if (theUser == null || !theUser.isEnabled()) {
            throw new LoginException("User unknown");
        }

        synchronized( theUser.getId().intern() )
        {
	        try {
	            AuthenticationSource authSource = theUser.getAuthenticationSource();

	            EPSJAASConfiguration configuration = new EPSJAASConfiguration(authSource.getProperties());
	            javax.security.auth.login.Configuration.setConfiguration(configuration);
	            LoginContext loginContext = new LoginContext(authSource.getJaasType(),
	                    new WebLoginCallbackHandler(theUser.getUserName(), loginPassword.toCharArray()));
	            loginContext.login();
	        } catch(LoginException ex) {
	            if(!userClassifier.isMasterAdmin(theUser)) {
	            	increaseFailedLogins(theUser);
	            }
	            throw ex;
	        }
        }
    }


    public void updateLoginPassword(final User user, final String newPassword)
            throws SQLException, GeneralSecurityException {
        user.setLoginPassword(newPassword);

        UserPasswordEncryptionHandler upe = new UserPasswordEncryptionHandler(newPassword);
        byte[] encryptedKey = KeyUtils.encryptKey(user.getAccessKey(), upe);

        try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(UPDATE_LOGIN_PASSWORD_SQL)) {
            int idx = 1;
            ps.setBytes(idx++, user.getPassword());

            Calendar now = Calendar.getInstance();
            ps.setLong(idx++, now.getTimeInMillis());
            ps.setBytes(idx++, encryptedKey);
            ps.setString(idx, user.getId());
            ps.executeUpdate();
        }
    }


    public List<User> getGroupMembers(Group group)
            throws SQLException {
        return getMultiple(GROUP_MEMBER_LIST_SQL, group.getGroupId());
    }

    //------------------------

    private static final class InstanceHolder {
    	static final UserDAO INSTANCE = new UserDAO();
    }

    public static UserDAO getInstance() {
		return InstanceHolder.INSTANCE;
    }
}
