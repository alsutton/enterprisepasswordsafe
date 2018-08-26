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
import java.io.Serializable;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Properties;

import com.enterprisepasswordsafe.engine.utils.PasswordUtils;
import com.enterprisepasswordsafe.proguard.ExternalInterface;

/**
 * Object representing a password.
 */

public final class Password
	extends PasswordBase
	implements Serializable, ExternalInterface {

	/**
	 * The parameter used to say if this password is enabled or not.
	 */

	private static final String ENABLED_PARAMETER = "_enabled";

	/**
	 * The parameter used to determine the auditing level for the password
	 */

	private static final String AUDIT_PARAMETER = "_audit";

	/**
	 * The parameter used to determine the history recording level
	 */

	private static final String HISTORY_RECORDING_PARAMETER = "_historyrecording";

	/**
	 * The parameter used to hold the restriction ID
	 */

	private static final String RESTRICTION_PARAMETER = "_restriction";

	/**
	 * The parameter used to hold the restricted access settings
	 */

	private static final String RESTRICTED_ACCESS_PARAMETER = "_ra";

	/**
	 * The parameter used to hold the password type
	 */

	private static final String TYPE_PARAMETER = "_type";

    /**
	 *
	 */
	private static final long serialVersionUID = -2231263119527545643L;

	/**
     * Object user to represent a user was imported without a problem.
     */

    public static final Object IMPORTED_OK = new Object();

    /**
     * The values for a password type.
     */

    public static final int TYPE_SYSTEM = 0,
    						TYPE_PERSONAL = 1;

    /**
     * The value used to indicate there is no logging on this password.
     */

    public static final int AUDITING_NONE = 0x00;

    /**
     * The value used to indicate log-only auditing.
     */

    public static final int AUDITING_LOG_ONLY = 0x01;

    /**
     * The value used to indicate email only auditing.
     */

    public static final int AUDITING_EMAIL_ONLY = 0x10;

    /**
     * The values used for setting the system auditing options
     */

    public static final String	SYSTEM_AUDIT_FULL = "F",
    							SYSTEM_AUDIT_LOG_ONLY = "L",
    							SYSTEM_AUDIT_EMAIL_ONLY = "E",
    							SYSTEM_AUDIT_NONE = "N",
    							SYSTEM_AUDIT_CREATOR_CHOOSE = "C";

    /**
     * The values used for setting the system password history voptions
     */

    public static final String	SYSTEM_PASSWORD_RECORD = "F",
    							SYSTEM_PASSWORD_DONT_RECORD = "L",
    							SYSTEM_PASSWORD_CREATOR_CHOOSE = "C";

	/**
     * The value used to indicate full auditing.
     */

    public static final int AUDITING_FULL = AUDITING_EMAIL_ONLY | AUDITING_LOG_ONLY;

    /**
     * The auditing level for this password.
     */
    private int auditLevel;

    /**
     * Whether or not this history is stored.
     */
    private boolean isHistoryStored;

    /**
     * The ID of the restriction for this password.
     */

    private String restrictionId;

    /**
     * Whether or not "Restricted Access" is enabled for this password
     */

    private boolean raEnabled = false;

    /**
     * The number of RA approvers required.
     */

    private int raApprovers = 0;

    /**
     * The number of RA blockers required.
     */

    private int raBlockers = 0;

    /**
     * The type of the password
     */

    private int passwordType = TYPE_SYSTEM;

    /*
     * Encrypted representation of the password properties
     */

    private byte[] encryptedPasswordProperties;

    public Password() throws NoSuchAlgorithmException, NoSuchProviderException {
    	super();
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
     *
     * @throws NoSuchAlgorithmException Thrown if the encryption algorithm is unavailable.
     * @throws NoSuchProviderException Thrown if the encryption provider is unavailable.
     */

    public Password(final String newUsername, final String newPassword,
            final String newLocation, final String newNotes)
        throws NoSuchAlgorithmException, NoSuchProviderException {
        this(null, newUsername, newPassword, newLocation, newNotes);
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
     * @param newAudited
     *            Whether or not the password is audited.
     * @param newHistoryStored
     *            Whether or not the history is stored for this password.
     * @param newExpiry
     *            The expiry date for the password.
     *
     * @throws NoSuchAlgorithmException Thrown if the encryption algorithm is unavailable.
     * @throws NoSuchProviderException Thrown if the encryption provider is unavailable.
     */

    public Password(final String newUsername, final String newPassword,
            final String newLocation, final String newNotes,
            final int newAudited, final boolean newHistoryStored,
            final long newExpiry)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        this(null, newUsername, newPassword, newLocation, newNotes,
                newAudited, newHistoryStored, newExpiry);
    }

    /**
     * Creates a new instance of Password.
     *
     * @param newPasswordId
     *            The id for the password.
     * @param newUsername
     *            The username to create the password with.
     * @param newPassword
     *            The password itself.
     * @param newLocation
     *            The location to associate with the password.
     * @param newNotes
     *            The notes to associate with the password.
     *
     * @throws NoSuchAlgorithmException Thrown if the encryption algorithm is unavailable.
     * @throws NoSuchProviderException Thrown if the encryption provider is unavailable.
     */

    public Password(final String newPasswordId, final String newUsername,
            final String newPassword, final String newLocation,
            final String newNotes)
        throws NoSuchAlgorithmException, NoSuchProviderException {
        this(newPasswordId, newUsername, newPassword, newLocation,
                newNotes, Password.AUDITING_FULL, false, Long.MAX_VALUE);
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
     * @param newAudited
     *            Whether or not the password is audited.
     * @param newHistoryStored
     *            Whether or not the history is stored for this password.
     * @param newExpiry
     *            The expiry date for the password.
     *
     * @throws NoSuchAlgorithmException Thrown if the encryption algorithm is unavailable.
     * @throws NoSuchProviderException Thrown if the encryption provider is unavailable.
     */

    public Password(final String newPasswordId, final String newUsername,
            final String newPassword, final String newLocation,
            final String newNotes, final int newAudited,
            final boolean newHistoryStored, final long newExpiry)
            throws NoSuchAlgorithmException, NoSuchProviderException {
        super(newPasswordId, newUsername, newPassword, newLocation, newNotes, newExpiry);

        setEnabled(true);
        auditLevel = newAudited;
        isHistoryStored = newHistoryStored;
    }

    public Password(final String passwordId, final byte[] data, final AccessControl ac)
            throws IOException, GeneralSecurityException, SQLException {
        super(passwordId);
        encryptedPasswordProperties = data;
        decryptPasswordProperties(ac);
    }

    public Password(final String passwordId, final byte[] data) {
        super(passwordId);
        encryptedPasswordProperties = data;
    }

    public void decryptPasswordProperties(AccessControl ac)
            throws IOException, GeneralSecurityException, SQLException {
        if (encryptedPasswordProperties == null) {
            // null indicates there's no work to be done to decrypt the properties.
            return;
        }

        Properties props = new Properties();
        PasswordUtils.decrypt(this, ac, encryptedPasswordProperties, props);

        String systemAuditState = ConfigurationDAO.getValue( ConfigurationOption.PASSWORD_AUDIT_LEVEL );
        if        ( systemAuditState.equals(Password.SYSTEM_AUDIT_NONE) ) {
            auditLevel = Password.AUDITING_NONE;
        } else if ( systemAuditState.equals(Password.SYSTEM_AUDIT_FULL) ) {
            auditLevel = Password.AUDITING_FULL;
        } else if ( systemAuditState.equals(Password.SYSTEM_AUDIT_LOG_ONLY) ) {
            auditLevel = Password.AUDITING_LOG_ONLY;
        } else {
            auditLevel = Password.AUDITING_FULL;

            String defaultAuditLevel = props.getProperty(AUDIT_PARAMETER);
            if (defaultAuditLevel != null) {
                if (defaultAuditLevel.equalsIgnoreCase("L")) {
                    auditLevel = Password.AUDITING_LOG_ONLY;
                } else if (defaultAuditLevel.equalsIgnoreCase("N")) {
                    auditLevel = Password.AUDITING_NONE;
                }
            }
        }

        String booleanFlag = props.getProperty(HISTORY_RECORDING_PARAMETER);
        isHistoryStored = (booleanFlag != null && booleanFlag.equals("Y"));

        restrictionId = props.getProperty(RESTRICTION_PARAMETER);

        String raState = props.getProperty(RESTRICTED_ACCESS_PARAMETER);
        if(raState != null && raState.charAt(0) == 'Y') {
            raEnabled = true;
            raApprovers = Integer.parseInt(props.getProperty(RESTRICTED_ACCESS_PARAMETER+"_a"));
            raBlockers = Integer.parseInt(props.getProperty(RESTRICTED_ACCESS_PARAMETER+"_b"));
        } else {
            raEnabled = false;
        }

        String passwordTypeString = props.getProperty(TYPE_PARAMETER);
        if(passwordTypeString != null) {
            passwordType = Integer.parseInt(passwordTypeString);
        }

        encryptedPasswordProperties = null;
    }

    /**
     * Get the audit state for this password.
     *
     * @return The audit state.
     */

    public int getAuditLevel() {
        return auditLevel;
    }

    /**
     * Gets the ID of the restriction associated with the password.
     *
     * @return The id of the restruction.
     */

    public String getRestrictionId() {
    	return restrictionId;
    }

    /**
     * Gets whether or not the history is stored.
     *
     * @return Returns the isHistoryStored.
     */
    public boolean isHistoryStored() {
        return isHistoryStored;
    }

    /**
     * @param auditLevel The isAudited to set.
     */
    public void setAuditLevel(final int auditLevel) {


        this.auditLevel = auditLevel;
    }

    /**
     * @param newIsHistoryStored The isHistoryStored to set.
     */
    public void setHistoryStored(final boolean newIsHistoryStored) {
        isHistoryStored = newIsHistoryStored;
    }

    /**
     * Set the applicable password restriction for this password.
     *
     * @param newRestrictionId The ID of the restriction to use.
     */
	public void setRestrictionId(String newRestrictionId) {
		restrictionId = newRestrictionId;
	}

	public int getRaApprovers() {
		return raApprovers;
	}

	public void setRaApprovers(int raApprovers) {
		this.raApprovers = raApprovers;
	}

	public int getRaBlockers() {
		return raBlockers;
	}

	public void setRaBlockers(int raBlockers) {
		this.raBlockers = raBlockers;
	}

	public boolean isRaEnabled() {
		return raEnabled;
	}

	public void setRaEnabled(boolean raEnabled) {
		this.raEnabled = raEnabled;
	}

	public int getPasswordType() {
		return passwordType;
	}

	public void setPasswordType(int passwordType) {
		this.passwordType = passwordType;
	}

	@Override
	public boolean isLoggable() {
		return (getPasswordType() == Password.TYPE_SYSTEM);
	}

	public void setCustomFields(final Map<String, String> fields) {
        Map<String, String> existingFields = getAllCustomFields();

        if(fields == null || fields.isEmpty()) {
            if(existingFields != null) {
                List<String> keysToRemove = new ArrayList<String>(existingFields.size());
                for(String key : existingFields.keySet()) {
                    keysToRemove.add(key);
                }
                for(String key : keysToRemove) {
                    deleteCustomField(key);
                }
            }
            return;
        }

        if(existingFields != null) {
            List<String> keysToRemove = new ArrayList<String>(existingFields.size());
            for(String key : getAllCustomFields().keySet()) {
                if(fields.get(key) == null) {
                    keysToRemove.add(key);
                }
            }
            for(String key : keysToRemove) {
                deleteCustomField(key);
            }
        }

		for(Map.Entry<String, String> entry : fields.entrySet()) {
			super.setCustomField(entry.getKey(), entry.getValue());
		}
	}

}
