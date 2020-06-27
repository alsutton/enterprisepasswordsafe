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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.sql.ResultSet;
import java.sql.SQLException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import com.enterprisepasswordsafe.engine.GroupAccessControlDecryptor;
import com.enterprisepasswordsafe.engine.utils.IDGenerator;

/**
 * Object representation of a group within the system.
 */
public final class Group
    implements Comparable<Group>, EntityWithAccessRights, GroupAccessControlDecryptor {

	/**
	 * The group statuses
	 */

	public static final int		STATUS_ENABLED = 0,
								STATUS_DISABLED = 1,
								STATUS_DELETED = 2;

    /**
     * The size of the group access key in bits.
     */

    private static final int GROUP_KEY_SIZE = 128;

    /**
     * The algorithm used for the group key.
     */

    private static final String GROUP_KEY_ALGORITHM = "AES";

    /**
     * The ID for the admin group.
     */

    public static final String ADMIN_GROUP_ID = "0";

    /**
     * Group use when removing an admin group from a Collection.
     */

    public static final Group ADMIN_GROUP = new Group(ADMIN_GROUP_ID, "Admin");

    /**
     * The ID for the sub-admin group.
     */

    public static final String SUBADMIN_GROUP_ID = "1";

    /**
     * The ID for the sub-admin group.
     */

    public static final String ALL_USERS_GROUP_ID = "2";

    /**
     * The ID for the non-viewing user group
     */

    public static final String NON_VIEWING_GROUP_ID = "3";

    /**
     * Object to represent a group was imported without a problem.
     */

    public static final Object IMPORTED_OK = new Object();

    /**
     * The ID for the group.
     */

    private final String groupId;

    /**
     * The name of the group.
     */

    private String groupName;

    /**
     * The access key used to decrpyt items.
     */

    private SecretKey accessKey;

    /**
     * The current groups status
     */

    private int status;

    private static ThreadLocal<Cipher> sEncryptionCipherThreadLocal = new ThreadLocal<Cipher>();

    /**
     * Creates a new instance of Group using the specified values.
     *
     * @param id
     *            The ID for the group.
     * @param name
     *            The name of the group.
     * @param generateKey
     *            True if the group key should be generated, false if not.
     */

    public Group(final String id, final String name, boolean generateKey)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        groupId = id;
        groupName = name;
        if( generateKey ) {
            generateKey();
        }
    }

    /**
     * Creates a new instance of Group using the specified values.
     *
     * @param id
     *            The ID for the group.
     * @param name
     *            The name of the group.
     */

    public Group(final String id, final String name) {
    	groupId = id;
    	groupName = name;
    }

    /**
     * Creates a new instance of Group using the name only. This method will
     * generate an ID and an AES key for the group.
     *
     * @param name The name of the group
     *
     * @throws NoSuchAlgorithmException Thrown if an encryption key can not be generated.
     */

    public Group(final String name)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        this(IDGenerator.getID(), name, true);
    }

    /**
     * Creates a new instance of Group using a JDBC ResultSet.
     *
     * @param rs
     *            The JDBC result set
     * @param startIdx
     *            The index of the start of the data.
     *
     * @throws SQLException Thrown if there is a problem extracting the
     *  data from the ResultSet.
     */

    public Group(final ResultSet rs, final int startIdx) throws SQLException {
        this(rs.getString(startIdx), rs.getString(startIdx + 1));
        status = rs.getInt(startIdx+2);
    }

    private Cipher getEncryptionCipher()
            throws NoSuchPaddingException, NoSuchAlgorithmException {
        Cipher cipher = sEncryptionCipherThreadLocal.get();
        if(cipher == null) {
            cipher = Cipher.getInstance(GROUP_KEY_ALGORITHM);
            sEncryptionCipherThreadLocal.set(cipher);
        }
        return cipher;
    }

    /**
     * Generates the read and modify keys.
     *
     * @throws NoSuchAlgorithmException Thrown if the encryption algorithm is not
     *  supported.
     */

    public void generateKey() throws NoSuchAlgorithmException {
        KeyGenerator kgen = KeyGenerator.getInstance(GROUP_KEY_ALGORITHM);
        kgen.init(GROUP_KEY_SIZE); // 192 and 256 bits may not be available
        accessKey = kgen.generateKey();
    }

    /**
     * Updates the access key from a group membership.
     *
     * @param membership
     *            The membership to extract the key from.
     */

    public void updateAccessKey(final Membership membership) {
        accessKey = membership.getAccessKey();
    }

    /**
     * Encodes some data using the groups access key.
     *
     * @param data The data to encrypt.
     *
     * @return The encrypted data.
     *
     * @throws GeneralSecurityException Thrown if there is a problem during encryption.
     * @throws UnsupportedEncodingException
     */

    public byte[] encrypt(final byte[] data)
        throws GeneralSecurityException {
        if (data == null) {
            return null;
        }

        // Update to method
        Cipher cipher = getEncryptionCipher();
        cipher.init(Cipher.ENCRYPT_MODE, accessKey);

        return cipher.doFinal(data);
    }

    /**
     * Decrypts some data using the groups access key.
     *
     * @param data The data to decrypt.
     *
     * @return The decrypted data.
     *
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the data.
     * @throws UnsupportedEncodingException
     */

	public byte[] decrypt(final byte[] data)
        throws GeneralSecurityException {
        if (data == null) {
            return null;
        }

        Cipher cipher = getEncryptionCipher();
        cipher.init(Cipher.DECRYPT_MODE, accessKey);

        return cipher.doFinal(data);
    }

    /**
     * The hash code for this group. This uses the groupId because it must be unique
     * to any specific group.
     *
     * @return The hash code for this group object.
     */

    @Override
	public int hashCode() {
        return groupId.hashCode();
    }

    /**
     * The equality test checks that the this group matches another object.
     *
     * @param otherObject The other object to test equality with.
     *
     * @return true If the Group objects are for the same group, false if not.
     */

    @Override
	public boolean equals(final Object otherObject) {
        if (!(otherObject instanceof Group)) {
            return false;
        }

        Group otherGroup = (Group) otherObject;
        return groupId.equals(otherGroup.groupId);
    }

    @Override
	public int compareTo(final Group otherGroup) {
        if (groupId.equals(otherGroup.groupId)) {
            return 0;
        }

        return groupName.compareToIgnoreCase(otherGroup.groupName);
    }

    /**
     * Returns whether or not this user is a enabled.
     *
     * @return true if the user is enabledr, false if not.
     */

    public boolean isEnabled() {
        return status == Group.STATUS_ENABLED;
    }

    /**
     * Get the status for this group.
     */

    public int getStatus() {
    	return status;
    }

    /**
     * Sets the group status.
     *
     * @param status The new status.
     */

    public void setStatus(final int status) {
    	this.status = status;
    }

    /**
     * Get the ID of this group.
     *
     * @return The ID of this group.
     */

    public String getGroupId() {
        return groupId;
    }
    @Override
    public String getId() {
        // TODO: Unify Id getters
        return getGroupId();
    }

    /**
     * Get the name of this group.
     *
     * @return The group name.
     */

    public String getGroupName() {
        return groupName;
    }

    /**
     * Set the name of this group.
     *
     * @param newGroupName The group name.
     */

    public void setGroupName(String newGroupName) {
        groupName = newGroupName;
    }

    /**
     * Gets the access key for this group.
     *
     * @return The access key for this group.
     */

    public SecretKey getAccessKey() {
        return accessKey;
    }

    /**
     * @param newAccessKey The accessKey to set.
     */
    public void setAccessKey(final SecretKey newAccessKey) {
        accessKey = newAccessKey;
    }

    /**
     * Gets the encrypter for this group.
     *
     * @return a Key encrypter for use with the key store.
     */

    @Override
	public Encrypter getKeyEncrypter() {
    	return new GroupKeyEncrypter(accessKey);
    }

    /**
     * Gets the encrypter for this group.
     *
     * @return a Key encrypter for use with the key store.
     */

    @Override
	public Decrypter getKeyDecrypter() {
    	return new GroupKeyDecrypter(accessKey);
    }

	/**
	 * Class which encrypts data using the key encryption algorithm
	 * and the users password.
	 */
	private class GroupKeyEncrypter implements Encrypter {

		/**
		 * The password to encrypt with.
		 */

		private final SecretKey encryptionKey;

		/**
		 * Constructor. Stores password
		 *
		 * @param key The key to use for encryption.
		 */

		private GroupKeyEncrypter(final SecretKey key) {
	        encryptionKey = key;
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
	        if (data == null) {
	            return null;
	        }

	        Cipher cipher = getEncryptionCipher();
	        cipher.init(Cipher.ENCRYPT_MODE, encryptionKey);
	        return cipher.doFinal(data);
		}
	}

	/**
	 * Class which encrypts data using the key encryption algorithm
	 * and the users password.
	 */
	private class GroupKeyDecrypter implements Decrypter {

		/**
		 * The password to encrypt with.
		 */

		private final SecretKey encryptionKey;

		/**
		 * Constructor. Stores password
		 *
		 * @param key The key to use for encryption.
		 */

		private GroupKeyDecrypter(final SecretKey key) {
	        encryptionKey = key;
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
	        if (data == null) {
	            return null;
	        }

	        Cipher cipher = getEncryptionCipher();
	        cipher.init(Cipher.DECRYPT_MODE, encryptionKey);
	        return cipher.doFinal(data);
		}
	}

}
