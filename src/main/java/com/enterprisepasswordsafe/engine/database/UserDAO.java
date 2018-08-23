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
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import com.enterprisepasswordsafe.engine.database.derived.UserSummary;
import com.enterprisepasswordsafe.engine.jaas.EPSJAASConfiguration;
import com.enterprisepasswordsafe.engine.jaas.WebLoginCallbackHandler;
import com.enterprisepasswordsafe.engine.users.UserPriviledgeTransitioner;
import com.enterprisepasswordsafe.engine.utils.Cache;
import com.enterprisepasswordsafe.engine.utils.KeyUtils;
import com.enterprisepasswordsafe.engine.utils.UserAccessKeyEncrypter;
import com.enterprisepasswordsafe.proguard.ExternalInterface;

/**
 * Data access object for the user objects.
 */
public final class UserDAO extends ObjectFetcher<User> implements ExternalInterface {

    /**
     * The SQL to get a count of the number of enabled users.
     */

    private static final String GET_COUNT_SQL =
            "SELECT count(*) "
            + " FROM application_users "
            + " WHERE disabled is null OR disabled = 'N'";

    /**
     * The fields relating to the user.
     */

    public static final String USER_FIELDS = "appusers.user_id, "
            + "appusers.user_name, appusers.user_pass_b, "
            + "appusers.email, appusers.full_name, "
            + "appusers.akey, appusers.aakey, "
            + "appusers.last_login_l, "
            + "appusers.auth_source, appusers.disabled, "
            + "appusers.pwd_last_changed_l";

    /**
     * The SQL to get a particular user by their ID.
     */

    private static final String GET_BY_ID_SQL =
            "SELECT " + USER_FIELDS
            + "  FROM application_users appusers "
            + " WHERE appusers.user_id = ? ";

    /**
     * The SQL statement to get a category.
     */

    private static final String GET_BY_NAME_SQL =
            "SELECT " + USER_FIELDS
            + "  FROM application_users appusers"
            + " WHERE appusers.user_name = ?"
            + "   AND (appusers.disabled is null OR appusers.disabled = 'N')";

    /**
     * The SQL statement to get all users.
     */

    private static final String GET_ENABLED_USERS_SQL =
            "SELECT " + USER_FIELDS
            + "  FROM application_users appusers "
            + " WHERE appusers.user_id <> '0' "
            + "   AND (appusers.disabled is null OR appusers.disabled = 'N')"
            + " ORDER BY appusers.user_name ASC";

    /**
     * The SQL statement to get all users even if they are disabled.
     */

    private static final String GET_ALL_USERS_SQL =
            "SELECT " + USER_FIELDS
            + "  FROM application_users appusers "
            + " WHERE appusers.user_id <> '"+User.ADMIN_USER_ID+"' AND appusers.disabled <> 'D'"
            + " ORDER BY appusers.user_name ASC";

    /**
     * The SQL write a users details to the database.
     */

    private static final String WRITE_SQL =
              "INSERT INTO application_users(" +
              "	user_id, " +
              "	user_name, " +
              " user_pass_b, " +
              " full_name, " +
              " email, " +
              " last_login_l, " +
              " disabled, " +
              " akey, "+
              " aakey " +
              ") VALUES( ?, ?, ?, ?, ?, ?, ?, ?, ? )";

    /**
     * The SQL write a users details to the database.
     */

    private static final String UPDATE_SQL =
              "UPDATE	application_users" +
              "   SET	user_name = ?, " +
              "			user_pass_b = ?, " +
              " 		full_name = ?, " +
              "			email = ?, " +
              "			last_login_l = ?, " +
              "			disabled = ?," +
              "			pwd_last_changed_l = ?, "+
              "			auth_source = ? "+
              " WHERE	user_id = ?";

    /**
     * The SQL to see if a user is member of a particular group.
     */

    private static final String DELETE_USER_SQL =
        "UPDATE application_users SET DISABLED = 'D' WHERE user_id = ? ";

    /**
     * The SQL to delete a users memberships.
     */

    private static final String DELETE_USER_MEMBERSHIPS =
            "DELETE FROM membership WHERE user_id = ?";

    /**
     * The SQL to delete a users memberships.
     */

    private static final String DELETE_UACS =
            "DELETE FROM user_access_control WHERE user_id = ?";

    /**
     * The SQL to delete a users memberships.
     */

    private static final String DELETE_UARS =
            "DELETE FROM hierarchy_access_control WHERE user_id = ?";

    /**
     * Update the admin access key for a user
     */

    private static final String UPDATE_ADMIN_ACCESS_KEY = "UPDATE application_users SET aakey = ? WHERE user_id = ?";

    /**
     * The array of SQL statements run to delete a user.
     */

    private static final String[] DELETE_SQL_STATEMENTS = {
            DELETE_UACS, DELETE_UARS, DELETE_USER_MEMBERSHIPS, DELETE_USER_SQL
    };

	private final UserPriviledgeTransitioner userPriviledgeTransitioner;

	/**
	 * Private constructor to prevent instantiation
	 */

	private UserDAO(UserPriviledgeTransitioner priviledgeTransitioner) {
	    super(GET_BY_ID_SQL, GET_BY_NAME_SQL);
        userPriviledgeTransitioner = priviledgeTransitioner;
	}

	User newInstance(ResultSet rs, int startIndex)
            throws SQLException {
	    return new User(rs, startIndex);
    }

    /**
     * Gets the administrator user using the admin group.
     *
     * @param adminGroup group The admin group.
     *
     * @return The admin user.
     */

    public User getAdminUser(final Group adminGroup)
    	throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
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
        String userId = user.getUserId();
        for(String statement : DELETE_SQL_STATEMENTS) {
            try(PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(statement)) {
                ps.setString(1, userId);
                ps.executeUpdate();
            }
        }
    }

    /**
     * Increase the number of failed logins.
     *
     * @param theUser The user to increase the failed login count for.
     */
    public void zeroFailedLogins( User theUser )
        throws SQLException {
    	theUser.setFailedLogins(0);
    }

    /**
     * Increase the number of failed logins.
     *
     * @param theUser The user to increase the failed login count for.
     */
    public void increaseFailedLogins( User theUser )
        throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
    	int loginAttempts = theUser.getLoginAttempts()+1;
    	theUser.setFailedLogins(loginAttempts);

        String maxAttempts = ConfigurationDAO.getValue(ConfigurationOption.LOGIN_ATTEMPTS);
        int maxAttemptsInt = Integer.parseInt(maxAttempts);
        if( loginAttempts >= maxAttemptsInt ) {
        	TamperproofEventLogDAO.getInstance().create(
            			TamperproofEventLog.LOG_LEVEL_USER_MANIPULATION,
	        			theUser,
	                    "The user "+ theUser.getUserName() +
	                    " has been disabled to due too many failed login attempts ("+loginAttempts+").",
	                    false
                    );
            theUser.setEnabled(false);
            update(theUser);
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

	    	if( theUser.getUserId().equals( User.ADMIN_USER_ID ) ) {
	    		Group adminGroup = GroupDAO.getInstance().getAdminGroup(theUser);

	            KeyGenerator kgen = KeyGenerator.getInstance(User.USER_KEY_ALGORITHM);
	            kgen.init(User.USER_KEY_SIZE);
	            SecretKey accessKey = kgen.generateKey();

	            Encrypter newEncrypter = new UserAccessKeyEncrypter(accessKey);
	            UserAccessControlDAO.getInstance().updateEncryptionOnKeys(theUser, newEncrypter);
	            MembershipDAO.getInstance().updateEncryptionOnKeys(theUser, newEncrypter);

	            theUser.setAccessKey(accessKey);
	            updateAdminKey(theUser, adminGroup);
	    	}

	    	theUser.updateLoginPassword(newPassword);
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
        	ps.setString(2, user.getUserId());
        	ps.execute();
        }
    }

    /**
     * Creates a user in the database.
     *
     * @param creatingUser The user who is creating the new user.
     * @param username The username of the new user.
     * @param password The password of the new user.
     * @param fullName The full name of the new user.
     * @param email The email of the new user.
     *
     * @return The new user as an object.
     */

    public User createUser(final User creatingUser,
            final String username, final String password, final String fullName,
            final String email)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        if (getByName(username) != null) {
            throw new GeneralSecurityException("The user already exists");
        }

        // Get the admin group from the creating user
        Group adminGroup = GroupDAO.getInstance().getAdminGroup(creatingUser);

        if(password == null || password.isEmpty()) {
            throw new GeneralSecurityException("The user must have a password");
        }

        // Create the user object
        User newUser = new User(username, password, fullName, email);
        write(newUser, adminGroup, password);

        // Write to the database and log creation
        zeroFailedLogins(newUser);
        TamperproofEventLogDAO.getInstance().create(
    			TamperproofEventLog.LOG_LEVEL_USER_MANIPULATION,
                creatingUser,
                "Created the user {user:"+ newUser.getUserId() + "}",
                true
            );

        Group allUsersGroup = GroupDAO.getInstance().getById(Group.ALL_USERS_GROUP_ID);
        if( allUsersGroup != null ) {
        	MembershipDAO mDAO = MembershipDAO.getInstance();
	        Membership theMembership = mDAO.getMembership(creatingUser, allUsersGroup);
	        allUsersGroup.updateAccessKey(theMembership);
	        mDAO.create(newUser, allUsersGroup);
        }

        String defaultSource = ConfigurationDAO.getValue(ConfigurationOption.DEFAULT_AUTHENTICATION_SOURCE_ID);
        newUser.setAuthSource(defaultSource);
        update(newUser);

        return newUser;
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
            ps.setString(1, theUser.getUserId());
            ps.setString(2, theUser.getUserName());
            ps.setBytes (3, theUser.getPassword());
            ps.setString(4, theUser.getFullName());
            ps.setString(5, theUser.getEmail());
            ps.setLong  (6, theUser.getLastLogin());
            ps.setString(7, "N");

            final byte[] keyData = theUser.getAccessKey().getEncoded();
            ps.setBytes (8, theUser.encryptWithPassword(initialPassword, keyData));
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
            if( theUser.isEnabled() ) {
            	ps.setString(6, "N");
            } else {
            	ps.setString(6, "Y");
            }
            ps.setLong  (7, theUser.getPasswordLastChanged());
            ps.setString(8, theUser.getAuthSource());
            ps.setString(9, theUser.getUserId());
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
        return getMultiple(GET_ALL_USERS_SQL, null);
    }

    /**
     * Gets a list of all enabled users.
     *
     * @return A List of all enabled users in the system.
     */

    public List<User> getEnabledUsers()
        throws SQLException {
        return getMultiple(GET_ENABLED_USERS_SQL, null);
    }

    /**
     * Count the number of active users in the system.
     *
     * @return The user count.
     */

    public int countActiveUsers( )
        throws SQLException, GeneralSecurityException
    {
        try (Statement statement = BOMFactory.getCurrentConntection().createStatement()) {
            try(ResultSet rs = statement.executeQuery(GET_COUNT_SQL)) {
	            if (!rs.next()) {
	                throw new GeneralSecurityException("The number of users you have in your database could not be counted.");
	            }

	            return rs.getInt(1);
            }
        }
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
		throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
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

        synchronized( theUser.getUserId().intern() )
        {
	        try {
	            AuthenticationSource authSource = AuthenticationSource.DEFAULT_SOURCE;
	            String userAuthSource = theUser.getAuthSource();
	            if (!theUser.getUserId().equals(User.ADMIN_USER_ID) && userAuthSource != null) {
	                authSource = AuthenticationSourceDAO.getInstance().getById(userAuthSource);
	            }

	            EPSJAASConfiguration configuration = new EPSJAASConfiguration(authSource.getProperties());
	            javax.security.auth.login.Configuration.setConfiguration(configuration);
	            LoginContext loginContext = new LoginContext(authSource.getJaasType(),
	                    new WebLoginCallbackHandler(theUser.getUserName(), loginPassword
	                            .toCharArray()));
	            loginContext.login();
	        } catch(LoginException ex) {
	            if(!theUser.getUserId().equals(User.ADMIN_USER_ID)) {
	            	increaseFailedLogins(theUser);
	            }
	            throw ex;
	        }
        }
    }

    //------------------------

    private static final class InstanceHolder {
    	static final UserDAO INSTANCE = new UserDAO(new UserPriviledgeTransitioner());
    }

    public static UserDAO getInstance() {
		return InstanceHolder.INSTANCE;
    }
}
