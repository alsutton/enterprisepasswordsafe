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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.ParseException;
import java.util.Calendar;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import com.enterprisepasswordsafe.engine.accesscontrol.AccessControl;
import com.enterprisepasswordsafe.engine.utils.DateFormatter;
import com.enterprisepasswordsafe.engine.utils.IDGenerator;
import com.enterprisepasswordsafe.engine.utils.PasswordUtils;

/**
 * Base class for objects relating to passwords.
 */
public abstract class PasswordBase
	implements Comparable<PasswordBase>, AccessControledObject {

    /**
     * Number of millisecons in a day.
     */
    private static final long MILLIS_IN_A_DAY = 24 * 60 * 60 * 1000;

    /**
     * The fields needed to construct a PasswordBase object from a ResultSet.
     */

    public static final String PASSWORD_BASE_FIELDS =
        " pass.password_id, pass.password_data ";

    /**
     * The number of ResultSet fields used by this object.
     */

    public static final int PASSWORD_BASE_FIELDS_COUNT = 2;

    /**
     * The state used when the expiry state of a password is unkown.
     */

    public static final int EXPIRY_UNKNOWN = -1;

    /**
     * The state used when the password has not expired.
     */

    public static final int EXPIRY_PASSED = 0;

    /**
     * The state used when the password is about to expire.
     */

    public static final int EXPIRY_WARN = 1;

    /**
     * The state used when the password has expired.
     */

    public static final int EXPIRY_OK = 2;

    /**
     * The encyrption algorythm used to encrypt passwords in the database.
     */

    public static final int PASSWORD_KEY_SIZE = 1024;

    /**
     * The algorythm used for encryption in version 1.
     */

    public static final String V1_PASSWORD_ALGORITHM = "RSA";

    /**
     * The ID for this password.
     */

    private String passwordId = null;

    /**
     * The username associated with this password.
     */

    private String username;

    /**
     * The password itself.
     */

    private String password;

    /**
     * The system on which the password resides.
     */

    private String location;

    /**
     * Notes associated with the password.
     */
    private String notes;

    /**
     * Whether or not the password is enabled.
     */

    private boolean enabled;

    /**
     * The expiry date for the password.
     */

    private long expiry = Long.MAX_VALUE;

    /**
     * The key used to modify the password.
     */
    private PrivateKey modifyKey;

    /**
     * The key used to read the password.
     */
    private PublicKey readKey;

    /**
     * Flag to say if the password is modifyable or not.
     */
    private boolean isModifiable;

    /**
     * The custom fields
     */

    private Map<String,String> customFields;

    /**
     * Constructor. Creates empty object ready for population.
     *
     * @throws NoSuchProviderException
     * @throws NoSuchAlgorithmException
     */

    public PasswordBase() throws NoSuchAlgorithmException, NoSuchProviderException {
        passwordId = IDGenerator.getID();
        generateKeys();
    }

    /**
     * Constructor. Creates empty object ready for population.
     */

    public PasswordBase(final String id) {
    	passwordId = id;
    }

    /**
     * Creates a new instance of Password.
     *
     * @param newUsername
     *            The username to create the password with.
     * @param newPassword
     *            The password itself.
     * @param newLocation
     *            The location to associate with the password.
     * @param newNotes
     *            The notes to associate with the password.
     * @param newExpiry
     *            The expiry date for the password.
     *
     * @throws NoSuchAlgorithmException Thrown if the encryption algorithm is unavailable.
     * @throws NoSuchProviderException Thrown if the encryption provider is unavailable.
     */

    public PasswordBase(final String newUsername, final String newPassword,
            final String newLocation, final String newNotes,
            final long newExpiry)
        throws NoSuchAlgorithmException, NoSuchProviderException {
        this(null, newUsername, newPassword, newLocation, newNotes, newExpiry);
    }

    /**
     * Creates a new instance of Password.
     *
     * @param newPasswordId
     *            The id of the password.
     * @param newUsername
     *            The username to create the password with.
     * @param newPassword
     *            The password itself.
     * @param newLocation
     *            The location to associate with the password.
     * @param newNotes
     *            The notes to associate with the password.
     * @param newExpiry
     *            The expiry date for the password.
     *
     * @throws NoSuchAlgorithmException Thrown if the encryption algorithm is unavailable.
     * @throws NoSuchProviderException Thrown if the encryption provider is unavailable.
     */

    public PasswordBase(final String newPasswordId, final String newUsername,
            final String newPassword, final String newLocation,
            final String newNotes, final long newExpiry)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        if (newPasswordId != null) {
            passwordId = newPasswordId;
        } else {
            passwordId = IDGenerator.getID();
            generateKeys();
        }

        setUsername(newUsername);
        setPassword(newPassword);
        setNotes(newNotes);
        setExpiry(newExpiry);

        if( newLocation != null ) {
        	location = newLocation;
        } else {
        	location = "";
        }

        isModifiable = false;
    }

    /**
     * Creates a new instance of Password.
     *
     * @param passwordId The ID for the password.
     * @param data The password data.
     * @param ac The access control for the password.
     * @param props The properties relating to the password.
     *
     */

    public PasswordBase(final String passwordId, final byte[] data, final AccessControl ac, final Properties props)
            throws IOException, GeneralSecurityException {
    	this.passwordId = passwordId;
    	PasswordUtils.decrypt(this, ac, data, props);
    }

    /**
     * Creates a new instance of Password.
     *
     * @param passwordId The ID for the password.
     * @param data The password data.
     * @param ac The access control for the password.
     */

    public PasswordBase(final String passwordId, final byte[] data, final AccessControl ac)
            throws IOException, GeneralSecurityException {
    	this(passwordId, data, ac, null);
    }

    /**
     * Decrypts this password using a given uac if it is encrypted.
     *
     * @param ac The access control to use to decrypt the password.
     */

    public final void decrypt(final AccessControl ac) {
        modifyKey = ac.getModifyKey();
        readKey = ac.getReadKey();

        isModifiable = (modifyKey != null);
    }

    /**
     * Generates the read and modify keys.
     *
     * @throws NoSuchAlgorithmException Thrown if the encryption algorithm is unavailable.
     * @throws NoSuchProviderException Thrown if the encryption provider is unavailable.
     */

    public final void generateKeys()
        throws NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance(V1_PASSWORD_ALGORITHM);
        kpg.initialize(PASSWORD_KEY_SIZE);
        KeyPair keys = kpg.generateKeyPair();

        modifyKey = keys.getPrivate();
        readKey = keys.getPublic();
    }

    /**
     * Gets the expiry state for the password.
     *
     * @return The expiry state.
     *
     * @throws ParseException Thrown if there is a problem parsing the expiry date.
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException
     */

    public final String getTimeToExpire()
        throws ParseException, UnsupportedEncodingException, GeneralSecurityException {
    	long theExpiry = getExpiry();
        if (theExpiry == Long.MAX_VALUE) {
            return "Never Expires";
        }

        long today = DateFormatter.getToday();
        if( today == theExpiry ) {
            return "Expiring Today";
        }

        if (today > theExpiry) {
            return "Expired";
        }

        Calendar now = Calendar.getInstance();
        long expiryDistance = theExpiry - now.getTimeInMillis();
        expiryDistance /= MILLIS_IN_A_DAY;
        expiryDistance++;
        if (expiryDistance == 0) {
            return "Expiring Today";
        }
        if (expiryDistance == 1) {
            return "Expires Tomorrow";
        }

        StringBuffer expiredString = new StringBuffer();
        expiredString.append("Expires in ");
        expiredString.append(expiryDistance);
        expiredString.append(" days");

        return expiredString.toString();
    }

    /**
     * Checks to see if the password has expired.
     *
     * @return true if the password has expired, false if not.
     * @throws GeneralSecurityException
     * @throws UnsupportedEncodingException
     */

    public final boolean isExpired() throws UnsupportedEncodingException, GeneralSecurityException {
        return getExpiry() < DateFormatter.getToday();
    }

    /**
     * Compares this password to another object.
     *
     * @param otherPassword
     *            The other object.
     * @return < 0 if the other object should be considered less than this, 0 if
     *         it should be considered equal, or > 0 if it should be considered
     *         greater than.
     */

    @Override
	public final int compareTo(final PasswordBase otherPassword) {
        int compareValue = username.compareTo(otherPassword.username);
        if (compareValue == 0) {
            compareValue = location.compareTo(otherPassword.location);
        }
        if (compareValue == 0) {
            compareValue = passwordId.compareTo(otherPassword.passwordId);
        }

        return compareValue;
    }

    /**
     * Get the hash code for this object. The passwordId should be unique for
     * all passwords, therefore we'll use it for the hash.
     *
     * @return The hash code for this object.
     */

    @Override
	public final int hashCode() {
        return passwordId.hashCode();
    }

    /**
     * Test this object for equality with another object.
     *
     * @param otherObject
     *            The object to compare this one to.
     *
     * @return true if the objects are equal, false if not.
     */

    @Override
	public final boolean equals(final Object otherObject) {
        return  otherObject != null
            && (otherObject instanceof PasswordBase)
            &&  passwordId.equals(((PasswordBase) otherObject).passwordId);
    }

    /**
     * Get the ID for this password.
     *
     * @return The ID for the password.
     */

    @Override
	public final String getId() {
        return passwordId;
    }

    /**
     * Set the ID for this password
     */

    public void setId(final String id) {
    	passwordId = id;
    }

    /**
     * Get the username for this password.
     *
     * @return The username for this password.
     */

    public final String getUsername() {
        return username;
    }

    /**
     * Get the password for this password.
     *
     * @return The password for this password.
     */

    public final String getPassword() {
        return password;
    }

    /**
     * Get the notes for this password.
     *
     * @return The notes for this password.
     */

    public final String getNotes() {
        return notes;
    }

    /**
     * Get the location for this password.
     *
     * @return The location for this password.
     */

    public final String getLocation() {
        return location;
    }

    /**
     * Get the expiry for this password.
     *
     * @return The expiry for this password.
     */

    public final long getExpiry() {
        return expiry;
    }

    /**
     * Sets whether or not the password is enabled.
     *
     * @param enabled true if the password should be considered enabled, false if not.
     */

    public void setEnabled(final boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * @return Returns the isEnabled.
     */
    public boolean isEnabled() {
        return enabled;
    }

    /**
     * Gets the expiry date in a readable format.
     */

    public final String getExpiryInHumanForm() {
    	return DateFormatter.convertToString( getExpiry() );
    }

    /**
     * Get the modification key for this password.
     *
     * @return The modification key for this password.
     */

    @Override
	public final PrivateKey getModifyKey() {
        return modifyKey;
    }

    /**
     * Get the read key for this password.
     *
     * @return The read key for this password.
     */

    @Override
	public final PublicKey getReadKey() {
        return readKey;
    }

    /**
     * @param newExpiry The expiry to set.
     */
    public final void setExpiry(final long newExpiry) {
        expiry = newExpiry;
    }

    /**
     * @param newLocation The location to set.
     */
    public final void setLocation(final String newLocation) {
    	if( newLocation != null ) {
    		location = newLocation;
    	} else {
    		location = "";
    	}

    }

    /**
     * @param newNotes The notes to set.
     */
    public final void setNotes(final String newNotes) {
        notes = newNotes;
    }

    /**
     * @param newPassword The password to set.
     */
    public final void setPassword(final String newPassword) {
        password = newPassword;
    }

    /**
     * @param newUsername The username to set.
     */
    public final void setUsername(final String newUsername) {
        username = newUsername;
    }

    /**
     * Add a custom field.
     *
     * @param name The name of the custom field.
     * @param value The value for the custom field.
     */

    public final void setCustomField(final String name, final String value) {
    	synchronized(this) {
    		if(customFields == null) {
    			customFields = new HashMap<String, String>();
    		}
    		customFields.put(name, value);
    	}
    }

    /**
     * Delete a custom field.
     *
     * @param name The name of the field to remove.
     */

    public final void deleteCustomField(final String name) {
        if(customFields != null) {
            customFields.remove(name);
        }
    }

    /**
     * Get a custom field value
     *
     * @param name The name of the custom field.
     *
     * @return The custom field value.
     */

    public final String getCustomField(final String name) {
    	synchronized(this) {
	    	if(customFields == null) {
	    		return null;
	    	}
	    	return customFields.get(name);
    	}
    }

    /**
     * Get all the custom fields
     *
     * @return The map of custom fields.
     */

    public Map<String,String> getAllCustomFields() {
    	return customFields;
    }

    /**
     * Add all the custom fields to a map.
     *
     * @param fields The Map to add the fields to.
     */

    public void addAllCustomFields(final Map<String,String> fields) {
    	for(Map.Entry<String,String> entry : fields.entrySet()) {
    		setCustomField(entry.getKey(), entry.getValue());
    	}
    }


    /**
     * Whether or not the password expires.
     *
     * @return true if the password has an expiry date, false if not.
     */

    public final boolean expires() {
    	return (expiry != Long.MAX_VALUE);
    }

    /**
     * Return if the password can be modified using the access control specified.
     *
     * @return Returns the isModifiable.
     */
    public final boolean isModifiable() {
        return isModifiable;
    }

    /**
     * toString method, prepares the content of this object in a human readable
     * form.
     *
     * @return The string represnting this object
     */

    @Override
	public String toString() {
        return getUsername() + '@' + getLocation();
    }

}
