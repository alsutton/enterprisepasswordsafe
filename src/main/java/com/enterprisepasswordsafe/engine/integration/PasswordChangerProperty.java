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

package com.enterprisepasswordsafe.engine.integration;

import com.enterprisepasswordsafe.proguard.ExternalInterface;

/**
 * Object holding the details of a property relevant to the password changer.
 */
public class PasswordChangerProperty implements ExternalInterface {

	/**
	 * The internal name of the property.
	 */
	
	private String internalName;
	
	/**
	 * The display name for the property.
	 */
	
	private String displayName;
	
	/**
	 * The description of the password
	 */
	
	private String description;
	
	/**
	 * The default value for the property.
	 */
	
	private String defaultValue;
	
	/**
	 * Constructor. Stores the supplied details.
	 */
	
	public PasswordChangerProperty( final String theInternalName,
			final String theDisplayName, final String theDescription,
			final String theDefaultValue )
	{
		internalName = theInternalName;
		displayName = theDisplayName;
		description = theDescription;
		defaultValue = theDefaultValue;
	}

	/**
	 * Get the default value for the property.
	 * 
	 * @return The default value for the property.
	 */
	public String getDefaultValue() {
		return defaultValue;
	}

	/**
	 * Get the description for the property.
	 * 
	 * @return The description of the property.
	 */
	public String getDescription() {
		return description;
	}

	/**
	 * Get the name to display for the property.
	 * 
	 * @return The display value for the property.
	 */
	public String getDisplayName() {
		return displayName;
	}

	/**
	 * Get the internal name for the property.
	 * 
	 * @return The internal name for the property.
	 */
	public String getInternalName() {
		return internalName;
	}
}
