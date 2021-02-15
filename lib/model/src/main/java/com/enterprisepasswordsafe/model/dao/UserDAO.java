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

package com.enterprisepasswordsafe.model.dao;

import com.alsutton.cryptography.Decrypter;
import com.enterprisepasswordsafe.model.*;
import com.enterprisepasswordsafe.model.cryptography.DecrypterFactory;
import com.enterprisepasswordsafe.model.cryptography.EncrypterFactory;
import com.enterprisepasswordsafe.model.persisted.AuthenticationSource;
import com.enterprisepasswordsafe.model.persisted.Group;
import com.enterprisepasswordsafe.model.persisted.Membership;
import com.enterprisepasswordsafe.model.persisted.User;

import javax.crypto.SecretKey;
import javax.persistence.EntityManager;
import javax.persistence.TypedQuery;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.List;

/**
 * Data access object for the user objects.
 */
public final class UserDAO extends JPADAOBase<User> {

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
     * The array of SQL statements run to delete a user.
     */

    private static final String[] DELETE_SQL_STATEMENTS = {
            DELETE_UACS, DELETE_UARS, DELETE_USER_MEMBERSHIPS, DELETE_USER_SQL
    };

    public UserDAO(DAORepository daoRepository, EntityManager entityManager) {
        super(daoRepository, entityManager, User.class);
    }

    public User getByName(String name) {
        return getWithSingleParameter("User.getByName", "name", name);
    }

    /**
     * Gets the administrator user using the admin group.
     *
     * @param adminGroup group The admin group.
     *
     * @return The admin user.
     */

    public User getAdminUser(final Group adminGroup)
    	throws GeneralSecurityException {
    	if(adminGroup == null || !ReservedGroups.ADMIN.matches(adminGroup)) {
    		throw new GeneralSecurityException("Attempt to get admin user with non-admin group");
    	}

        User adminUser = getById(ReservedUsers.ADMIN.getId());
        Decrypter decrypter = new DecrypterFactory(adminGroup).decrypterFor(adminUser);
        adminUser.decryptKey(adminUser::getEncryptedAdminAccessKey, decrypter);

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
    	throws GeneralSecurityException {
    	Group adminGroup = daoRepository.getGroupDAO().getAdminGroup(theUser);
    	return getAdminUser(adminGroup);
    }

    /**
     * Mark a user as deleted.
     *
     * @param user The user to mark as deleted.
     */

    public void delete( final User user ) {
        user.setState(EntityState.DELETED);
    }

    /**
     * Update the users login password.
     *
     * @param theUser The user being updated.
     * @param newPassword The new password.
     */

    public void updatePassword(User theUser, String newPassword )
    	throws UnsupportedEncodingException, SQLException, GeneralSecurityException {
    }


    public User createUser(final User creatingUser, final User newUser, final String password,
                           final String email)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        if(password == null || password.isEmpty()) {
            throw new GeneralSecurityException("The user must have a password");
        }

        if (getByName(newUser.getName()) != null) {
            throw new GeneralSecurityException("The user already exists");
        }

        // Get the admin group from the creating user
        Group adminGroup = daoRepository.getGroupDAO().getAdminGroup(creatingUser);

        // Create the user object
        write(newUser, adminGroup, password);

        Group allUsersGroup = daoRepository.getGroupDAO().getById(ReservedGroups.ALL_USERS);
        if( allUsersGroup != null ) {
        	MembershipDAO mDAO = daoRepository.getMembershipDAO();
	        Membership theMembership = mDAO.getMembership(creatingUser, allUsersGroup);
	        allUsersGroup.setKey(theMembership.getKey());
	        mDAO.create(newUser, allUsersGroup);
        }

        Long defaultSource =
                daoRepository.getConfigurationDAO().getLongValue(ConfigurationOptions.DEFAULT_AUTHENTICATION_SOURCE_ID);
        AuthenticationSource authenticationSource =
                daoRepository.getAuthenticationSourceDAO().getById(defaultSource);
        newUser.setAuthenticationSource(authenticationSource);
        store(creatingUser);

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
        byte[] encodedKey = theUser.getKey().getEncoded();
        theUser.setEncryptedAccessKey(new EncrypterFactory(theUser).encrypterFor(theUser).apply(encodedKey));
        theUser.setEncryptedAdminAccessKey(new EncrypterFactory(theUser).encrypterFor(adminGroup).apply(encodedKey));
        store(theUser);
    }

    /**
     * Gets a list of all users.
     *
     * @return A List of all users in the system.
     */

    public List<User> getAll() {
        TypedQuery<User> fetchAllQuery =
                entityManager.createQuery("SELECT u FROM User u", User.class);
        return fetchAllQuery.getResultList();
    }

    /**
     * Gets a list of all enabled users.
     *
     * @return A List of all enabled users in the system.
     */

    public List<User> getEnabledUsers() {
        TypedQuery<User> getEnabledQuery =
                entityManager.createQuery("SELECT u FROM User u WHERE u.state = :state", User.class);
        getEnabledQuery.setParameter("state", EntityState.ENABLED);
        return getEnabledQuery.getResultList();
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
		User user = getById(userId);
		if(user == null) {
			return null;
		}
		Decrypter decrypter = new DecrypterFactory(adminGroup).decrypterFor(user);
		SecretKey key = user.decryptKey(user::getEncryptedAdminAccessKey, decrypter);
        user.setKey(key);
		return user;
	}
}
