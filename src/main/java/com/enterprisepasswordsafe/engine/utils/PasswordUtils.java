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

package com.enterprisepasswordsafe.engine.utils;

import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.GeneralSecurityException;
import java.util.IllegalFormatException;
import java.util.Map;
import java.util.Properties;

import com.enterprisepasswordsafe.engine.accesscontrol.AccessControl;
import com.enterprisepasswordsafe.engine.database.Password;
import com.enterprisepasswordsafe.engine.database.PasswordBase;

/**
 * Utilities for altering the way a password is represented.
 *
 * @author alsutton
 *
 */
public final class PasswordUtils<T extends PasswordBase> {
	/**
	 * The property name used to store the username
	 */

	private static final String USERNAME_PROPERTY = "_username";

	/**
	 * The property name used to store the location
	 */

	private static final String LOCATION_PROPERTY = "_location";

	/**
	 * The property name used to store the password
	 */

	private static final String PASSWORD_PROPERTY = "_password";

	/**
	 * The property name used to store the notes
	 */

	private static final String NOTES_PROPERTY = "_notes";

	/**
	 * The property name used to store the notes
	 */

	private static final String ENABLED_PROPERTY = "_enabled";

    /**
     * The property name used to store the notes
     */

    private static final String EXPIRY_PROPERTY = "_expiry";

	/**
	 * Encrypt the data in a password
	 *
	 * @param password The password.
	 * @param ac The access control to use.
	 *
	 * @return The encrypted representation
	 *
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	public static byte[] encrypt(final PasswordBase password, final AccessControl ac)
		throws IOException, GeneralSecurityException {
    	Properties passwordProperties = new Properties();
        passwordProperties.setProperty(ENABLED_PROPERTY, Boolean.toString(password.isEnabled()));
    	passwordProperties.setProperty(USERNAME_PROPERTY, password.getUsername());
    	passwordProperties.setProperty(LOCATION_PROPERTY, password.getLocation());
    	passwordProperties.setProperty(PASSWORD_PROPERTY, password.getPassword());
    	passwordProperties.setProperty(NOTES_PROPERTY,    password.getNotes());
    	if(password.getExpiry() != Long.MAX_VALUE) {
    		passwordProperties.setProperty(EXPIRY_PROPERTY,   Long.toString(password.getExpiry()));
    	}

        Map<String,String> customFields = password.getAllCustomFields();
        if(customFields != null) {
	        for(Map.Entry<String, String> entry : customFields.entrySet()) {
	        	passwordProperties.setProperty(entry.getKey(), entry.getValue());
	        }
        }

    	StringWriter sw = new StringWriter();
    	try {
    		passwordProperties.store(sw, null);

    		return ac.encrypt(sw.toString());
    	} finally {
    		sw.close();
    	}
	}

	/**
	 * Decrypt the data in a password
	 *
	 * @param password The password to set the values in
	 * @param ac The access control to use.
	 * @param data The password data
	 *
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	public T decrypt(final T password, final AccessControl ac, final byte[] data)
		throws IOException, GeneralSecurityException {
		decrypt(password, ac, data, new Properties());
		return password;
	}

	/**
	 * Decrypt the data in a password
	 *
	 * @param ac The access control to use.
	 * @param data The password data
	 *
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	public Password decrypt(final AccessControl ac, final byte[] data)
		throws IOException, GeneralSecurityException {
        Password password = new Password();
		decrypt(password, ac, data, new Properties());
		return password;
	}

	/**
	 * Decrypt the data in a password
	 *
	 * @param password The password to set the values in
	 * @param ac The access control to use.
	 * @param data The password data
	 *
	 * @throws IOException
	 * @throws GeneralSecurityException
	 */
	public static void decrypt(final PasswordBase password, final AccessControl ac,
                                     final byte[] data, final Properties passwordProperties)
		throws IOException, GeneralSecurityException {
        password.decrypt(ac);
		String propertiesString = ac.decrypt(data);
		passwordProperties.load(new StringReader(propertiesString));

        password.setEnabled(Boolean.parseBoolean(passwordProperties.getProperty(ENABLED_PROPERTY,"true")));
		password.setUsername(passwordProperties.getProperty(USERNAME_PROPERTY));
		password.setLocation(passwordProperties.getProperty(LOCATION_PROPERTY));
		password.setPassword(passwordProperties.getProperty(PASSWORD_PROPERTY));
		password.setNotes   (passwordProperties.getProperty(NOTES_PROPERTY));
		try {
			String expiryProperty = passwordProperties.getProperty(EXPIRY_PROPERTY);
			if(expiryProperty != null) {
				password.setExpiry(Long.parseLong(expiryProperty));
			}
		} catch(IllegalFormatException ife) {
			// Do nothing, constructor sets the value to the non-expiring default.
		}

		for(String propertyName : passwordProperties.stringPropertyNames()) {
			if(!propertyName.startsWith("_")) {
				password.setCustomField(propertyName, passwordProperties.getProperty(propertyName));
			}
		}
	}
}
