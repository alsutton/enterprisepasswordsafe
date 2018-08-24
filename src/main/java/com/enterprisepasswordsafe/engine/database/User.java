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
import java.security.*;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Calendar;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.enterprisepasswordsafe.engine.UserAccessControlDecryptor;
import com.enterprisepasswordsafe.engine.utils.DatabaseConnectionUtils;
import com.enterprisepasswordsafe.engine.utils.IDGenerator;
import com.enterprisepasswordsafe.engine.utils.KeyUtils;
import com.enterprisepasswordsafe.engine.utils.UserAccessKeyEncrypter;
import com.enterprisepasswordsafe.proguard.ExternalInterface;


/**
 * Object representing a user in the system.
 */
public final class User
    implements Comparable<User>, EntityWithAccessRights, UserAccessControlDecryptor, ExternalInterface {

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
     * The algorithm used for the password hash.
     */

    private static final String PASSWORD_HASH_ALGORITHM = "MD5";

    /**
     * The algorythm for the secure random number generator.
     */

    private static final String PBE_ALGORYTHM = "PBEWithMD5AndDES";

    /**
     * The salt used for PBE.
     */

    private static final byte[] PBE_SALT = {(byte) 0xc7, (byte) 0x73,
            (byte) 0x21, (byte) 0x8c, (byte) 0x7e, (byte) 0xc8, (byte) 0xee,
            (byte) 0x99 };

    /**
     * The number of iterations for PBE.
     */

    private static final int PBE_ITERATIONS = 3;

    /**
     * The user types for EPS users.
     */

    public static final int USER_TYPE_UNKNOWN = -1,
                            USER_TYPE_ADMIN = 0,
                            USER_TYPE_SUBADMIN   = 0x01,
                            USER_TYPE_NORMAL     = 0x02,
                            USER_TYPE_NONVIEWING = 0x10;
    /**
     * A mask which ensures only the user type details are returned.
     */

    private static final int ACTUAL_TYPE_MASK = 0x0F;

    /**
     * The ID for the admin user.
     */

    public static final String ADMIN_USER_ID = "0";

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
     * The SQL to get the number of login attempts for a user.
     */

    private static final String GET_LOGIN_ATTEMPTS_SQL =
            "SELECT	  appusers.login_attempts "
            + "  FROM application_users appusers "
            + " WHERE appusers.user_id = ? ";

    /**
     * The SQL to update the login password.
     */

    private static final String UPDATE_LOGIN_PASSWORD_SQL =
        "UPDATE application_users "
        + " SET user_pass_b = ?, pwd_last_changed_l = ?, akey = ? "
        + " WHERE user_id = ?";

    /**
     * Set the number of failed login attempts.
     */

    private static final String SET_LOGIN_FAILURE_COUNT =
        "UPDATE application_users "
      + "   SET login_attempts = ?"
      + " WHERE  user_id = ? ";

    /**
     * A cached value to store the user type.
     */

    private int userType = User.USER_TYPE_UNKNOWN;

    /**
     * The ID of this user.
     */

    private String userId;

    /**
     * The users login name.
     */

    private String userName;

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

    private long lastLogin;

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

    private static ThreadLocal<Cipher> sEncryptionCipherThreadLocal = new ThreadLocal<Cipher>();

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
     * @throws UnsupportedEncodingException
     */
    public User(final String newUserName, final String newPassword,
            final String newFullName, final String newEmail)
        throws NoSuchAlgorithmException, UnsupportedEncodingException {
        userId = IDGenerator.getID();
        userName = newUserName;
        fullName = newFullName;
        email = newEmail;
        lastLogin = 0;
        authSource = null;
        disabled = false;

        setLoginPassword(newPassword);

        generateKey();

        setUserType(USER_TYPE_NORMAL);
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

        getUserTypeFromDatabase();
    }

    private Cipher getEncryptionCipher()
            throws NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = sEncryptionCipherThreadLocal.get();
        if(cipher == null) {
            cipher = Cipher.getInstance(USER_KEY_ALGORITHM);
            sEncryptionCipherThreadLocal.set(cipher);
        }
        return cipher;
    }

    /**
     * Get the type for this user.
     *
     * @return one of the user types which relates to this user.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    private int getUserTypeFromDatabase()
        throws SQLException {
        if (userType != User.USER_TYPE_UNKNOWN) {
            return userType;
        }

        userType = User.USER_TYPE_NORMAL;
        MembershipDAO mDAO = MembershipDAO.getInstance();
        if (mDAO.isMemberOf(userId, Group.ADMIN_GROUP_ID)) {
            userType = User.USER_TYPE_ADMIN;
        } else if (mDAO.isMemberOf(userId, Group.SUBADMIN_GROUP_ID)) {
            userType = User.USER_TYPE_SUBADMIN;
        }

        if(!getUserId().equals(User.ADMIN_USER_ID)
        && mDAO.isMemberOf(userId, Group.NON_VIEWING_GROUP_ID)) {
            userType |= USER_TYPE_NONVIEWING;
        }

        return userType;
    }

    /**
     * Set the user type
     *
     * @param type type for the user.
     */

    private void setUserType(final int type) {
        userType = userType & (~ACTUAL_TYPE_MASK);
        userType |= type;
    }

    /**
     * Generates the read and modify keys.
     *
     * @throws NoSuchAlgorithmException Thrown if the access key algorithm is not available.
     */

    public void generateKey() throws NoSuchAlgorithmException {
        KeyGenerator kgen = KeyGenerator.getInstance(USER_KEY_ALGORITHM);
        kgen.init(USER_KEY_SIZE);
        accessKey = kgen.generateKey();
    }

    /**
     * Encodes some data using the users access key.
     *
     * @param data
     *            The data to encrypt.
     *
     * @return The encrypted data.
     *
     * @throws GeneralSecurityException Thrown if there is a problem encyrpting the data.
     * @throws UnsupportedEncodingException
     */

    public byte[] encrypt(final String data)
        throws GeneralSecurityException, UnsupportedEncodingException {
        if (data == null) {
            return null;
        }
        return encrypt(data.getBytes());
    }

    /**
     * Encodes some data using the users access key.
     *
     * @param data
     *            The data to encrypt.
     *
     * @return The encrypted data.
     *
     * @throws GeneralSecurityException Thrown if there is a problem encyrpting the data.
     */

    public byte[] encrypt(final byte[] data)
        throws GeneralSecurityException {
        Cipher cipher = getEncryptionCipher();
        cipher.init(Cipher.ENCRYPT_MODE, accessKey);
        return cipher.doFinal(data);
    }

    /**
     * Decrypts some data using the users access key.
     *
     * @param data
     *            The data to decrypt.
     *
     * @return The decrypted data.
     *
     * @throws GeneralSecurityException Thrown if there is a problem during decryption.
     */

    @Override
    public byte[] decrypt(final byte[] data)
        throws GeneralSecurityException {
        Cipher cipher = getEncryptionCipher();
        cipher.init(Cipher.DECRYPT_MODE, accessKey);
        return cipher.doFinal(data);
    }

    /**
     * Encrypts the data using a given password.
     *
     * @param encryptionPassword
     *            The password to encrypt the data with.
     * @param data
     *            The data to encrypt
     *
     * @return The encryption data.
     *
     * @throws GeneralSecurityException Thrown if there is a problem during the encryption
     */

    public byte[] encryptWithPassword(final String encryptionPassword, final byte[] data)
            throws GeneralSecurityException {
        PBEParameterSpec pbeParamSpec = new PBEParameterSpec(PBE_SALT, PBE_ITERATIONS);
        PBEKeySpec pbeKeySpec = new PBEKeySpec(encryptionPassword.toCharArray());
        SecretKeyFactory keyFac = SecretKeyFactory.getInstance(PBE_ALGORYTHM);
        SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
        Cipher pbeCipher = Cipher.getInstance(PBE_ALGORYTHM);
        pbeCipher.init(Cipher.ENCRYPT_MODE, pbeKey, pbeParamSpec);

        return pbeCipher.doFinal(data);
    }

    /**
     * Encrypts the data using a given password.
     *
     * @param decryptionPassword
     *            The password to encrypt the data with.
     * @param data
     *            The data to encrypt
     *
     * @return The decrypted data.
     *
     * @throws GeneralSecurityException Thrown if there is a problem during decryption.
     */

    public byte[] decryptWithPassword(final String decryptionPassword, final byte[] data)
            throws GeneralSecurityException {
        PBEParameterSpec pbeParamSpec = new PBEParameterSpec(PBE_SALT, PBE_ITERATIONS);
        PBEKeySpec pbeKeySpec = new PBEKeySpec(decryptionPassword.toCharArray());
        SecretKeyFactory keyFac = SecretKeyFactory.getInstance(PBE_ALGORYTHM);
        SecretKey pbeKey = keyFac.generateSecret(pbeKeySpec);
        Cipher pbeCipher = Cipher.getInstance(PBE_ALGORYTHM);
        pbeCipher.init(Cipher.DECRYPT_MODE, pbeKey, pbeParamSpec);

        return pbeCipher.doFinal(data);
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
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    public void setEnabled(final boolean isEnabled) {
        disabled = !isEnabled;
    }

    public AuthenticationSource getAuthenticationSource()
            throws SQLException {
        String userAuthSource = getAuthSource();
        if (!isMasterAdmin() && userAuthSource != null) {
            return AuthenticationSourceDAO.getInstance().getById(userAuthSource);
        } else {
            return AuthenticationSource.DEFAULT_SOURCE;
        }
    }

    public boolean isMasterAdmin() {
        return ADMIN_USER_ID.equals(userId);
    }


    /**
     * Returns whether or not this user is a administrator.
     *
     * @return true if the user is an administrator, false if not.
     */

    public boolean isAdministrator()
        throws SQLException {
    	return ((getUserTypeFromDatabase()&ACTUAL_TYPE_MASK) == User.USER_TYPE_ADMIN);
    }

    /**
     * Checks to see if the user should be given subadministrator rights.
     *
     * @return true if the user is a subadministrator, false if not.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    public boolean isSubadministrator()
        throws SQLException {
        return ((getUserTypeFromDatabase()&ACTUAL_TYPE_MASK) == User.USER_TYPE_SUBADMIN);
    }

    /**
     * Checks to see if the user should not be allowed to view passwords
     *
     * @return true if the user should not be allowed to view passwords, false if they should.
     *
     * @throws java.sql.SQLException
     */

    public boolean isNonViewingUser()
        throws SQLException {
        return (!getUserId().equals(ADMIN_USER_ID)) && ((getUserTypeFromDatabase() & USER_TYPE_NONVIEWING) != 0);
    }

    /**
     * Creates the password hash from a password.
     *
     * @param salt The salt to use for the has creation
     * @param userPassword The password to create the hash string for.
     *
     * @return the hash value for the password.
     *
     * @throws NoSuchAlgorithmException Thrown if the hash algorithm is unavailable.
     * @throws UnsupportedEncodingException
     */

    private byte[] createHash(final byte[] salt, final String userPassword)
            throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest digester = MessageDigest.getInstance(PASSWORD_HASH_ALGORITHM);

        byte[] passwordBytes = userPassword.getBytes();
        if(salt != null) {
            byte[] saltedBytes = new byte[salt.length + passwordBytes.length];
            System.arraycopy(passwordBytes, 0, saltedBytes, 0, passwordBytes.length);
            System.arraycopy(salt, 0, saltedBytes, passwordBytes.length, salt.length);
            passwordBytes = saltedBytes;
        }

        digester.update(passwordBytes);
        return digester.digest();
    }

    /**
     * Sets the users login password.
     *
     * @param newPassword
     *            The password to set it to.
     *
     * @throws NoSuchAlgorithmException Thrown if the hash algorithm is unavailable.
     * @throws UnsupportedEncodingException
     */

    public void setLoginPassword(final String newPassword)
            throws NoSuchAlgorithmException, UnsupportedEncodingException {
        byte[] salt = new byte[4];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(salt);

        byte[] hash = createHash(salt, newPassword);

        byte[] newPasswordBytes = new byte[2 + salt.length + hash.length];
        newPasswordBytes[0] = 2;
        newPasswordBytes[1] = (byte) salt.length;
        System.arraycopy(salt, 0, newPasswordBytes, 2, salt.length);
        System.arraycopy(hash, 0, newPasswordBytes, 2+salt.length, hash.length);

        password = newPasswordBytes;
    }


    /**
     * Update the users login password.
     *
     * @param newPassword The new password.
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     * @throws GeneralSecurityException Thrown if there is a problem re-encrypting the users data.
     * @throws UnsupportedEncodingException
     */

    public void updateLoginPassword(final String newPassword)
            throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        setLoginPassword(newPassword);

        UserPasswordEncrypter upe = new UserPasswordEncrypter(newPassword);
        byte[] encryptedKey = KeyUtils.encryptKey(accessKey, upe);

        PreparedStatement ps = null;
        try {
            int idx = 1;
            ps = BOMFactory.getCurrentConntection().prepareStatement(UPDATE_LOGIN_PASSWORD_SQL);
            ps.setBytes(idx++, password);

        	Calendar now = Calendar.getInstance();
            ps.setLong(idx++, now.getTimeInMillis());
            ps.setBytes(idx++, encryptedKey);
            ps.setString(idx, userId);
            ps.executeUpdate();
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
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
     * @throws UnsupportedEncodingException
     */

    public boolean checkPassword(final char[] userPassword)
            throws NoSuchAlgorithmException, UnsupportedEncodingException {
        return checkPassword(new String(userPassword));
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
     * @throws UnsupportedEncodingException
     */

    public boolean checkPassword(final String userPassword)
            throws NoSuchAlgorithmException, UnsupportedEncodingException {
        if (userPassword == null) {
            return false;
        }

        byte[] salt;
        byte[] hash;
        byte[] password = getPassword();
        switch (password[0]) {
            case 1:
                salt = null;
                hash = new byte[password.length-1];
                System.arraycopy(password, 1, hash, 0, hash.length);
                break;
            case 2:
                int saltLength = (int)password[1];
                salt = new byte[saltLength];
                System.arraycopy(password,2,salt,0,saltLength);
                hash = new byte[password.length - (saltLength+2)];
                System.arraycopy(password,2+saltLength,hash,0,hash.length);
                break;
            default:
                throw new RuntimeException("Unknown password encoding");
        }

        byte[] calculatedHash = createHash(salt, userPassword);

        return Arrays.equals(calculatedHash, hash);
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
     * @throws UnsupportedEncodingException
     */
    public void decryptAccessKey(final String decryptionPassword)
        throws GeneralSecurityException, UnsupportedEncodingException {
    	if( accessKey != null ) {
    		return;
    	}

		if( encodedAccessKey == null ) {
			throw new RuntimeException("Encoded access key unavailable, access key not present.");
		}

		byte[] keyBytes = decryptWithPassword(decryptionPassword, encodedAccessKey);
		accessKey = new SecretKeySpec(keyBytes, USER_KEY_ALGORITHM);
    }

    /**
     * Decrypts the admin access key using the admin group.
     *
     * @param adminGroup The group to decrypt the access key with.
     *
     * @throws UnsupportedEncodingException
     */
    public void decryptAdminAccessKey(final Group adminGroup)
        throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
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

    /**
     * @return Returns the loginAttempts.
     */
    public int getLoginAttempts()
    	throws SQLException {
    	int attempts = 0;

    	PreparedStatement ps = BOMFactory.getCurrentConntection().prepareStatement(GET_LOGIN_ATTEMPTS_SQL);
    	ResultSet rs = null;
    	try {
    		ps.setString(1, getUserId());
    		rs = ps.executeQuery();
    		if( rs.next() ) {
    			int fetchedAttempts = rs.getInt(1);
    			if(!rs.wasNull()) {
    				attempts = fetchedAttempts;
    			}
    		}
    	} finally {
    		DatabaseConnectionUtils.close(rs);
    		DatabaseConnectionUtils.close(ps);
    	}
        return attempts;
    }

    /**
     * @return Returns the password.
     */
    public byte[] getPassword() {
        return password;
    }

    /**
     * @return Returns the userId.
     */
    public String getUserId() {
        return userId;
    }

    @Override
    public String getId() {
        // TODO: Unify ID getters
        return getUserId();
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
     * Method to set the number of failed login attempts.
     *
     * @param count The number of failed login attempts.
     */

    public void setFailedLogins( int count )
    	throws SQLException {
        Connection conn = BOMFactory.getCurrentConntection();
    	PreparedStatement ps = conn.prepareStatement(SET_LOGIN_FAILURE_COUNT);
        try {
            ps.setInt(1, count);
            ps.setString(2, getUserId());
            ps.executeUpdate();
        } finally {
            DatabaseConnectionUtils.close(ps);
        }
    }

    /**
     * Gets the decryptor for this user which uses the admin key.
     *
     * @return The decryptor.
     */

    @Override
	public Decrypter getKeyDecrypter() {
    	return new UserAccessKeyDecrypter(getAccessKey());
    }

    /**
     * Gets the decryptor for this user which uses the admin key.
     *
     * @return The decryptor.
     */

    @Override
	public Encrypter getKeyEncrypter() {
    	return new UserAccessKeyEncrypter(getAccessKey());
    }

	/**
	 * Class which encrypts data using the key encryption algorithm
	 * and the users password.
	 */
	private class UserPasswordEncrypter implements Encrypter {

		/**
		 * The password to encrypt with.
		 */

		private final SecretKey encryptionKey;

		/**
		 * Constructor. Stores password
		 * @throws NoSuchAlgorithmException
		 */

		private UserPasswordEncrypter(final String password)
			throws GeneralSecurityException {
	        PBEKeySpec pbeKeySpec = new PBEKeySpec(password.toCharArray());
	        SecretKeyFactory keyFac = SecretKeyFactory.getInstance(PBE_ALGORYTHM);
	        encryptionKey = keyFac.generateSecret(pbeKeySpec);
		}

		/**
		 * Method to perform the encryption.
		 *
		 * @param data The data to encrypt.
		 *
		 * @return The encrypted representation of the data.
		 */

		@Override
		public byte[] encrypt(byte[] data)
			throws GeneralSecurityException {
	        PBEParameterSpec pbeParamSpec = new PBEParameterSpec(PBE_SALT, PBE_ITERATIONS);
	        Cipher pbeCipher = Cipher.getInstance(PBE_ALGORYTHM);
	        pbeCipher.init(Cipher.ENCRYPT_MODE, encryptionKey, pbeParamSpec);
	        return pbeCipher.doFinal(data);
		}
	}


	/**
	 * Class which decrypts data using the users access key.
	 */
	private static class UserAccessKeyDecrypter implements Decrypter {

		/**
		 * The password to encrypt with.
		 */

		private final SecretKey decryptionKey;

		/**
		 * Constructor. Stores password
		 */

		private UserAccessKeyDecrypter(final SecretKey newKey) {
			decryptionKey = newKey;
		}

		/**
		 * Method to perform the encryption.
		 *
		 * @param data The data to encrypt.
		 *
		 * @return The encrypted representation of the data.
		 */

		@Override
		public byte[] decrypt(byte[] data)
			throws GeneralSecurityException {
			Cipher pbeCipher = getCipher();
	        pbeCipher.init(Cipher.DECRYPT_MODE, decryptionKey);
	        return pbeCipher.doFinal(data);
		}

		/**
		 * ThreadLocal storing cipher instance for version one decryption.
		 */

		private static ThreadLocal<Cipher> cipherThreadLocal = new ThreadLocal<Cipher>();

		private Cipher getCipher() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
            Cipher result = cipherThreadLocal.get();
			if( result == null ) {
				result = Cipher.getInstance("AES");
                cipherThreadLocal.set(result);
			}
			return result;
		}
	}
}
