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
import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.enterprisepasswordsafe.engine.AccessControlDecryptor;
import com.enterprisepasswordsafe.engine.utils.Constants;
import com.enterprisepasswordsafe.engine.utils.KeyUtils;
import com.enterprisepasswordsafe.proguard.JavaBean;

/**
 * Base class providing functionality common to Group and User access controls.
 */
public abstract class AccessControl
	implements Comparable<AccessControl>, JavaBean {

    /**
     * The key size for the second level AES key in bits.
     */

    public static final int AES_KEY_SIZE_IN_BITS = 128;

    /**
     * The number of bits in a byte as used by the JCE provider.
     */

    private static final int JCE_PROVIDER_BITS_PER_BYTE = 8;

    /**
     * The number of columns from a ResultSet needed to create this object.
     */

    public static final int ACCESS_CONTROL_FIELD_COUNT = 4;

    /**
     * The first level encryption algorithm
     */

    private static final String FIRST_LEVEL_ENCRYPTION_ALGORITHM = "RSA";

    /**
     * The encryption algorithm used for second level encryption.
     */

    private static final String SECOND_LEVEL_ENCRYPTION_ALGORITHM = "AES";

    /**
     * SQL to get the item IDs a user has access to via a uac.
     */

    private static final String GET_UAC_ACCESSIBLE_ITEMS =
        "SELECT item_id "
        + "  FROM user_access_control "
        + " WHERE user_id = ? "
        + "   AND rkey IS NOT NULL";

    /**
     * SQL to get the item IDs a user has access to via a uac.
     */

    private static final String GET_GAC_ACCESSIBLE_ITEMS =
        "SELECT gac.item_id "
        + "  FROM   group_access_control gac, "
        + "         membership mem, "
        + "         group g "
        + " WHERE mem.user_id = ? "
        + " AND mem.group_id = g.group_id "
        + " AND (g.enabled is null OR g.enabled = 'Y') "
        + "   AND gac.group_id = mem.group_id "
        + " AND gac.rkey IS NOT NULL";

    public static final String READ_PERMISSION = "R";
    public static final String MODIFY_PERMISSION = "RM";

    /**
     * The ID of the accessing entity.
     */

    private String accessorId;

    /**
     * The ID of the item this access control is for.
     */

    private String itemId;

    /**
     * The modification key object.
     */

    private PrivateKey modifyKey;

    /**
     * The read key object.
     */

    private PublicKey readKey;

    /**
     * Null constructor. Useful for creating re-usable objects.
     */

    public AccessControl() {
    	super();
    }

    /**
     * Constructor. Stores information passed to it.
     *
     * @param newItemId The ID of the item this AC is for.
     * @param newModifyKey The modification key.
     * @param newReadKey The read key.
     */
    public AccessControl(final String newItemId, final String newAccessorId,
            final PrivateKey newModifyKey, final PublicKey newReadKey) {
        itemId = newItemId;
        accessorId = newAccessorId;
        modifyKey = newModifyKey;
        readKey = newReadKey;
    }

    /**
     * Constructor. Extracts the necessary information from a ResultSet
     *
     * @param rs The ResultSet to extract the data from.
     * @param startIdx The index in the ResultSet where the data starts.
     * @param decryptor The decryptor used to decrypt the access keys.
     *
     * @throws SQLException Thrown if there is a problem accessing the data.
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the data.
     * @throws UnsupportedEncodingException
     */
    public AccessControl(final ResultSet rs, final int startIdx, final AccessControlDecryptor decryptor)
        throws SQLException, GeneralSecurityException, UnsupportedEncodingException {
        int currentIdx = startIdx;
        itemId = rs.getString(currentIdx++);
        byte[] keyBytes = rs.getBytes(currentIdx++);
        if(!rs.wasNull()) {
        	modifyKey = KeyUtils.decryptPrivateKey(keyBytes, decryptor.getKeyDecrypter());
        }
        keyBytes = rs.getBytes(currentIdx++);
        if(!rs.wasNull()) {
        	readKey = KeyUtils.decryptPublicKey(keyBytes, decryptor.getKeyDecrypter());
        }
        accessorId = rs.getString(currentIdx);
    }

    /**
     * Encodes some data using the modify key.
     *
     * @param data The data to encrypt.
     *
     * @return The encrypted data.
     *
     * @throws GeneralSecurityException Thrown if there is a problem during encryption.
     * @throws UnsupportedEncodingException
     */

    public final byte[] encrypt(final String data)
    throws GeneralSecurityException, UnsupportedEncodingException {
    	if( data == null ) {
    		return null;
    	}
        return encryptToBinary(data);
    }

    /**
     * Encodes some data using the modify key.
     *
     * @param data The data to encrypt.
     *
     * @return The encrypted data.
     *
     * @throws GeneralSecurityException Thrown if there is a problem during encryption.
     * @throws UnsupportedEncodingException
     */

    public final byte[] encryptToBinary(final String data)
    throws GeneralSecurityException, UnsupportedEncodingException {
        if (modifyKey == null) {
            throw new GeneralSecurityException("Illegal attempt to update an object");
        }

        // Decrypt the data
        Cipher cipher = Cipher.getInstance(FIRST_LEVEL_ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, modifyKey);

        // Convert it into a string
        byte[] secondLevelKey = generateSecondLevelKey();
        byte[] encryptedKey = cipher.doFinal(secondLevelKey);

        // Encrypt the data.
        byte[] encryptedData = secondLevelEncrypt(secondLevelKey, data);

        // Combine the two blocks into one
        byte[] finalData = new byte[encryptedKey.length + encryptedData.length];
        System.arraycopy(encryptedKey, 0, finalData, 0, encryptedKey.length);
        System.arraycopy(encryptedData, 0, finalData, encryptedKey.length, encryptedData.length);

        return finalData;
    }

    /**
     * Generates the second level encryption key.
     *
     * @return The second level encryption key.
     *
     * @throws NoSuchAlgorithmException Thrown if the encryption algorithm is unavailable.
     */

    private byte[] generateSecondLevelKey()
    throws NoSuchAlgorithmException {
        KeyGenerator kgen = KeyGenerator.getInstance(SECOND_LEVEL_ENCRYPTION_ALGORITHM);
        kgen.init(AES_KEY_SIZE_IN_BITS);             // 192 and 256 bits may not be available
        SecretKey skey = kgen.generateKey();
        return skey.getEncoded();
    }

    /**
     * Encodes some data using the users access key.
     *
     * @param accessKey The key to encrypt the data with.
     * @param data The data to encrypt.
     *
     * @return The encrypted data.
     *
     * @throws GeneralSecurityException Thrown if there is a problem during encryption.
     * @throws UnsupportedEncodingException
     */

    private byte[] secondLevelEncrypt(final byte[] accessKey, final String data)
        throws GeneralSecurityException, UnsupportedEncodingException {
        if (data == null) {
            return null;
        }

        SecretKeySpec skeySpec = new SecretKeySpec(accessKey, SECOND_LEVEL_ENCRYPTION_ALGORITHM);
        Cipher cipher = Cipher.getInstance(SECOND_LEVEL_ENCRYPTION_ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);

        byte[] encrypted = cipher.doFinal(data.getBytes(Constants.STRING_CODING_FORMAT));
        return encrypted;
    }

    /**
     * Decrypts some data using the read key.
     *
     * @param data The data to decrypt.
     *
     * @return The decrypted data.
     *
     * @throws GeneralSecurityException Thrown if tehre is a problem during decrytpion.
     * @throws UnsupportedEncodingException
     */

    public final String decrypt(final byte[] data)
        throws GeneralSecurityException, UnsupportedEncodingException {
    	if( data == null) {
    		return null;
    	}

        return decryptFromBinary(data);
    }

    /**
     * Decrypts some data using the read key.
     *
     * @param data The data to decrypt.
     *
     * @return The decrypted data.
     *
     * @throws GeneralSecurityException Thrown if tehre is a problem during decrytpion.
     * @throws UnsupportedEncodingException
     */

    public final String decryptFromBinary(final byte[] data)
        throws GeneralSecurityException, UnsupportedEncodingException {
        byte[] decryptedData = decryptVersionTwoData(data);
	    return new String(decryptedData, Constants.STRING_CODING_FORMAT);
    }

    /**
     * Decrypts some data using the read key.
     *
     * @param data The data to decrypt.
     *
     * @return The decrypted data.
     *
     * @throws GeneralSecurityException Thrown if tehre is a problem during decrytpion.
     */

    private byte[] decryptVersionTwoData(final byte[] data)
        throws GeneralSecurityException {
        if (readKey == null) {
            throw new GeneralSecurityException("Illegal attempt to read an object");
        }

        // Extract the second level key and decode it.
        byte[] keyData = decryptVersionOneData(data, 0, AES_KEY_SIZE_IN_BITS);

        // This is needed because the bouncy castle provider drops leading zeros.
        int encryptionKeySizeByes =  AES_KEY_SIZE_IN_BITS / JCE_PROVIDER_BITS_PER_BYTE;
        int missingBytes = encryptionKeySizeByes - keyData.length;
        if (missingBytes != 0) {
            byte[] oldkeyData = keyData;
            keyData = new byte[encryptionKeySizeByes];
            int i = 0;
            for (; i < missingBytes; i++) {
                keyData[i] = 0;
            }
            System.arraycopy(oldkeyData, 0, keyData, i, oldkeyData.length);
        }

        SecretKeySpec skeySpec = new SecretKeySpec(keyData, SECOND_LEVEL_ENCRYPTION_ALGORITHM);

        // Decrypt the remaining data
        Cipher cipher = AccessControl.getVersionTwoCipher();
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        return cipher.doFinal(data, AES_KEY_SIZE_IN_BITS, (data.length - AES_KEY_SIZE_IN_BITS));
    }

    /**
     * Decrypts some data using the read key.
     *
     * @param data The data to decrypt.
     * @param start The start byte in the array to start decryption at.
     * @param length The number of bytes in the array to decrypt.
     *
     * @return The decrypted data.
     *
     * @throws GeneralSecurityException Thrown if there is a problem decrypting the data.
     */

    private byte[] decryptVersionOneData(final byte[] data, final int start, final int length)
        throws GeneralSecurityException {
        if (readKey == null) {
            throw new GeneralSecurityException("Illegal attempt to read an object");
        }

        // Decrypt the data
        Cipher cipher = AccessControl.getVersionOneCipher();
        cipher.init(Cipher.DECRYPT_MODE, readKey);

        // Convert it into a string
        byte[] original = cipher.doFinal(data, start, length);
        return original;
    }

    /**
     * Gets the list of item IDs a user has access to.
     *
     * @param conn The connection to the database.
     * @param userId The ID of the user to fetch the item IDs for.
     *
     * @return The List of item IDs
     *
     * @throws SQLException Thrown if there is a problem accessing the database.
     */

    public static List<String> getAccessibleItemIDs(final Connection conn, final String userId)
        throws SQLException {
        List<String> ids = new ArrayList<String>();
        getData(conn, userId, ids, AccessControl.GET_UAC_ACCESSIBLE_ITEMS);
        getData(conn, userId, ids, AccessControl.GET_GAC_ACCESSIBLE_ITEMS);
        return ids;
    }

    /**
     * Adds the IDs of the items returned by the specified query to a
     * specified List.
     *
     * @param conn The connection to the database.
     * @param userId The ID to get the data for.
     * @param list The list to store the data into.
     * @param statement The SQL to execute.
     *
     * @throws SQLException Thrown if there is a problem accessing the data.
     */

    private static void getData(final Connection conn, final String userId,
            final List<String> list, final String statement)
        throws SQLException {
        try(PreparedStatement ps = conn.prepareStatement(statement)) {
            ps.setString(1, userId);
            try(ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    list.add(rs.getString(1));
                }
            }
        }
    }

    /**
     * Get the item ID this access control relates to.
     *
     * @return the item ID.
     */

    public final String getItemId() {
        return itemId;
    }

    /**
     * Get the read key for this access control.
     *
     * @return The read key.
     */

    public final PublicKey getReadKey() {
        return readKey;
    }

    /**
     * Set the read key for this access control.
     *
     * @param newKey The new read key.
     */

    public final void setReadKey(final PublicKey newKey) {
        readKey = newKey;
    }

    /**
     * Get the modify key for this access control.
     *
     * @return The modify key.
     */

    public final PrivateKey getModifyKey() {
        return modifyKey;
    }

    /**
     * Set the modify key for this access control.
     *
     * @param newKey The modify key.
     */

    public final void setModifyKey(final PrivateKey newKey) {
        modifyKey = newKey;
    }

    /**
     * Compare this access control to another object.
     *
     * @param otherObject The other object.
     *
     * @return A comparison of their equality.
     */
	@Override
	public int compareTo(final AccessControl otherAc) {
		int itemIdComparison = itemId.compareTo(otherAc.itemId);
		if( itemIdComparison != 0 ) {
			return itemIdComparison;
		}

		int comparison = compareKeys(modifyKey, otherAc.modifyKey);
		if (comparison != 0) {
		    return comparison;
        }

        return compareKeys(readKey, otherAc.readKey);
	}

	private int compareKeys(Key thisKey, Key otherKey) {
        if( thisKey == null ) {
            if( otherKey != null ) {
                return Integer.MIN_VALUE;
            }
        } else {
            if( otherKey == null ) {
                return Integer.MAX_VALUE;
            }
        }
	    return 0;
    }

	public String getAccessorId() {
		return accessorId;
	}

	public void setAccessorId(String accessorId) {
		this.accessorId = accessorId;
	}

	public void setItemId(String itemId) {
		this.itemId = itemId;
	}

	/**
	 * ThreadLocal storing cipher instance for version two decryption.
	 */

	private static ThreadLocal<Cipher> versionTwoCipher = new ThreadLocal<Cipher>();

	protected static Cipher getVersionTwoCipher() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		Cipher cipher = versionTwoCipher.get();
		if( cipher == null ) {
			cipher = Cipher.getInstance(SECOND_LEVEL_ENCRYPTION_ALGORITHM);
			versionTwoCipher.set(cipher);
		}
		return cipher;
	}

	/**
	 * ThreadLocal storing cipher instance for version one decryption.
	 */

	private static ThreadLocal<Cipher> versionOneCipher = new ThreadLocal<Cipher>();

	protected static Cipher getVersionOneCipher() throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException {
		Cipher cipher = versionOneCipher.get();
		if( cipher == null ) {
			cipher = Cipher.getInstance(FIRST_LEVEL_ENCRYPTION_ALGORITHM);
			versionOneCipher.set(cipher);
		}
		return cipher;
	}
}
