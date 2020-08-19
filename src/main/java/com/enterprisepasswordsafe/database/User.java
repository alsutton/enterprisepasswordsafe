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

import com.enterprisepasswordsafe.engine.AccessControlDecryptor;
import com.enterprisepasswordsafe.engine.users.PasswordHasher;
import com.enterprisepasswordsafe.engine.users.UserAccessKeyEncryptionHandler;
import com.enterprisepasswordsafe.engine.users.UserClassifier;
import com.enterprisepasswordsafe.engine.users.UserPasswordEncryptionHandler;
import com.enterprisepasswordsafe.engine.utils.IDGenerator;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.sql.ResultSet;
import java.sql.SQLException;

/**
 * Object representing a user in the system.
 */
public final class User
    implements Comparable<User>, EntityWithAccessRights, AccessControlDecryptor {

    /**
     * The size of the group access key in bits.
     */

    public static final int USER_KEY_SIZE = 128;

    /**
     * The password last changed value designed to force a password change.
     */

    public static final long PASSWORD_LAST_CHANGED_FORCE = Long.MIN_VALUE;

    /**
     * The dummy value for when the password last changed has not been initialised.
     */

    private static final long PASSWORD_LAST_CHANGED_DUMMY = 1;

    /**
     * The value to use when users are deleted.
     */

    protected static final String DELETED_VALUE = "D";

    /**
     * The algorithm used for the group key.
     */

    static public final String USER_KEY_ALGORITHM = "AES";

    /**
     * The ID of this user.
     */

    private final String userId;

    /**
     * The users login name.
     */

    private final String userName;

    /**
     * The users Email address.
     */

    private String email;

    /**
     * The users full name.
     */

    private String fullName;

    /**
     * The users password.
     */

    private byte[] password;

    /**
     * The users access key.
     */

    private SecretKey accessKey = null;

    /**
     * The encoded access key.
     */

    private byte[] encodedAccessKey;

    /**
     * The encoded access key.
     */

    private byte[] encodedAdminAccessKey;

    /**
     * The last time the user logged on.
     */

    private final long lastLogin;

    /**
     * The authentication source for the user.
     */

    private String authSource;

    /**
     * The last time the users password was changed.
     */

    private long passwordLastChanged;

    /**
     * Flag to say if the user has been disabled.
     */

    private boolean disabled;

    private final PasswordHasher passwordHasher = new PasswordHasher();

    /**
     * Creates a new User object.
     *
     * @param newUserName The name of the user.
     * @param newPassword The users password.
     * @param newFullName The users full name.
     * @param newEmail The users email.
     *
     * @throws NoSuchAlgorithmException Thrown if there is a problem generating the users
     *  access key.
     */
    public User(final String newUserName, final String newPassword,
            final String newFullName, final String newEmail)
        throws NoSuchAlgorithmException {
        userId = IDGenerator.getID();
        userName = newUserName;
        fullName = newFullName;
        email = newEmail;
        lastLogin = 0;
        authSource = null;
        disabled = false;

        setLoginPassword(newPassword);

        KeyGenerator kgen = KeyGenerator.getInstance(USER_KEY_ALGORITHM);
        kgen.init(USER_KEY_SIZE);
        accessKey = kgen.generateKey();
    }

    /**
     * Creates an instance of a user object from a ResultSet.
     *
     * @param rs
     *            The ResultSet to extract the data from.
     * @param startIdx
     *            The start index of the data in the result set.
     *
     * @throws SQLException Thrown if there is a problem extracting the data from the ResultSet.
     */
    public User(final ResultSet rs, final int startIdx)
        throws SQLException {
        int idx = startIdx;
        userId = rs.getString(idx++);
        userName = rs.getString(idx++);
        password = rs.getBytes(idx++);
        email = rs.getString(idx++);
        fullName = rs.getString(idx++);
        encodedAccessKey = rs.getBytes(idx++);
        encodedAdminAccessKey = rs.getBytes(idx++);
        lastLogin = rs.getLong(idx++);
        authSource = rs.getString(idx++);

        String isDisabled = rs.getString(idx++);
        disabled = !(rs.wasNull() || isDisabled.charAt(0) == 'N');

        passwordLastChanged = rs.getLong(idx);
        if( rs.wasNull() ) {
        	passwordLastChanged = PASSWORD_LAST_CHANGED_DUMMY;
        }
    }

    /**
     * Compares this object to another object. If the other object is a user it
     * compares the user_name with the other objects user_name, if it's not then
     * it compares hash codes.
     *
     * @param otherUser The other user to compare this one to.
     *
     * @return <0 if the other object is considered of a lesser value, 0 if it is
     *         equals, or >0 if it is greater than the value of this object.
     */

    @Override
	public int compareTo(final User otherUser) {
    	return userName.compareToIgnoreCase(otherUser.userName);
    }

    /**
     * Generate the hash code for this user. Due to the ID being unique the
     * hash code of the id is used.
     *
     * @return The hash code for this object.
     */

    @Override
	public int hashCode() {
        return userId.hashCode();
    }

    /**
     * Check to see if another object is equal to this one.
     *
     * @param o
     *            The other object.
     * @return true if the objects are equal, false if not.
     */

    @Override
	public boolean equals(final Object o) {
        if (!(o instanceof User)) {
            return false;
        }

        User otherUser = (User) o;
        return otherUser.userId.equals(userId);
    }

    /**
     * Returns whether or not this user is a enabled.
     *
     * @return true if the user is enabled, false if not.
     */

    public boolean isEnabled() {
        return !disabled;
    }

    /**
     * Sets the user enablement flag.
     *
     * @param isEnabled true if the user should be enabled, false if not.
     */

    public void setEnabled(final boolean isEnabled) {
        disabled = !isEnabled;
    }

    public AuthenticationSource getAuthenticationSource()
            throws SQLException {
        String userAuthSource = getAuthSource();
        if (!new UserClassifier().isMasterAdmin(this) && userAuthSource != null) {
            return AuthenticationSourceDAO.getInstance().getById(userAuthSource);
        } else {
            return AuthenticationSource.DEFAULT_SOURCE;
        }
    }

    public void setLoginPassword(final String newPassword)
            throws NoSuchAlgorithmException {
        password = passwordHasher.createHashWithRandomSalt(newPassword);
    }

    /**
     * Forces the user to change their password at the next login.
     */

    public void forcePasswordChangeAtNextLogin( ) {
    	passwordLastChanged =  PASSWORD_LAST_CHANGED_FORCE;
	}

    /**
     * Whether or not the password given is the users password.
     *
     * @param userPassword
     *            The password to test.
     *
     * @return true if the password is correct, false if not.
     *
     * @throws NoSuchAlgorithmException Thrown if the password hashing algorithm is unavailable.
     */

    public boolean checkPassword(final char[] userPassword)
            throws NoSuchAlgorithmException {
        return checkPassword(new String(userPassword));
    }

    public boolean checkPassword(final String password)
            throws NoSuchAlgorithmException {
        if (password == null) {
            return false;
        }
        return passwordHasher.equalsSaltedHash(password, getPassword());
    }

    /**
     * Get the AccessKey.
     *
     * @return Returns the accessKey.
     */
    public SecretKey getAccessKey() {
        return accessKey;
    }

    /**
     * Set the AccessKey.
     *
     * @param newKey The access key to use.
     */
    public void setAccessKey(SecretKey newKey) {
        accessKey = newKey;
    }

    /**
     * Decrypts the access key using the specified password.
     *
     * @param decryptionPassword The to decrypt the access key with.
     */
    public void decryptAccessKey(final String decryptionPassword)
        throws GeneralSecurityException {
    	if( accessKey != null ) {
    		return;
    	}

		if( encodedAccessKey == null ) {
			throw new RuntimeException("Encoded access key unavailable, access key not present.");
		}

		byte[] keyBytes = new UserPasswordEncryptionHandler(decryptionPassword).decrypt(encodedAccessKey);
		accessKey = new SecretKeySpec(keyBytes, USER_KEY_ALGORITHM);
    }

    /**
     * Decrypts the admin access key using the admin group.
     *
     * @param adminGroup The group to decrypt the access key with.
     */
    public void decryptAdminAccessKey(final Group adminGroup)
        throws GeneralSecurityException {
    	if( accessKey != null ) {
    		return;
    	}

		if( encodedAdminAccessKey == null ) {
			throw new RuntimeException("Encoded admin access key unavailable, access key not present.");
		}

		byte[] keyBytes = adminGroup.getKeyDecrypter().decrypt( encodedAdminAccessKey );
		accessKey = new SecretKeySpec(keyBytes, USER_KEY_ALGORITHM);
    }

    /**
     * @return Returns the authSource.
     */
    public String getAuthSource() {
        return authSource;
    }

    /**
     * @return Returns the email.
     */
    public String getEmail() {
        return email;
    }

    /**
     * @return Returns the fullName.
     */
    public String getFullName() {
        return fullName;
    }

    /**
     * @return Returns the lastLogin.
     */
    public long getLastLogin() {
        return lastLogin;
    }

    public byte[] getPassword() {
        return password;
    }

    @Override
    public String getId() {
        return userId;
    }

    /**
     * @return Returns the userName.
     */
    public String getUserName() {
        return userName;
    }

    /**
     * Gets the last time the users password was changed
     *
     * @return A String for the last time a users password was changed.
     */

    public long getPasswordLastChanged() {
    	return passwordLastChanged;
    }

    /**
     * Prints this user name.
     *
     * @return A string representation of the user.
     */

    @Override
	public String toString() {
        String theUsername = userName;
        if (theUsername == null) {
            theUsername = "<<UNKNOWN USER>>";
        }

        return theUsername;
    }

    /**
     * @param newAuthSource The authSource to set.
     */
    public void setAuthSource(final String newAuthSource) {
        authSource = newAuthSource;
    }

    /**
     * @param newEmail The email to set.
     */
    public void setEmail(final String newEmail) {
        email = newEmail;
    }

    /**
     * @param newFullName The fullName to set.
     */
    public void setFullName(final String newFullName) {
        fullName = newFullName;
    }

    /**
     * Gets the decryptor for this user which uses the admin key.
     *
     * @return The decryptor.
     */

    @Override
	public Decrypter getKeyDecrypter() {
    	return new UserAccessKeyEncryptionHandler(getAccessKey());
    }

    /**
     * Gets the decryptor for this user which uses the admin key.
     *
     * @return The decryptor.
     */

    @Override
	public Encrypter getKeyEncrypter() {
    	return new UserAccessKeyEncryptionHandler(getAccessKey());
    }

}
