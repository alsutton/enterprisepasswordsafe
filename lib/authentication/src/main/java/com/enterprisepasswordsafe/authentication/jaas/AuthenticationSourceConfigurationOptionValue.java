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

package com.enterprisepasswordsafe.authentication.jaas;

/**
 * Class holding the details of an option in a multi-option authication source list.
 */

public class AuthenticationSourceConfigurationOptionValue 
	implements Comparable<AuthenticationSourceConfigurationOptionValue> {

	/**
	 * The name to show the user.
	 */
	
	private final String displayName;
	
	/**
	 * The value for this option
	 */
	
	private final String value;

	/**
	 * Constructor. Stores the values passed.
	 */
	
	public AuthenticationSourceConfigurationOptionValue(final String newDisplayName,
			final String newValue ) {
		displayName = newDisplayName;
		value = newValue;
	}
	
	/**
	 * Get the display name for this option.
	 * 
	 * @return The name to display to the user.
	 */
	
	public String getDisplayName() {
		return displayName;
	}

	/**
	 * Get the value for this option.
	 * 
	 * @return The value for this option.
	 */
	public String getValue() {
		return value;
	}
	
	/**
	 * Compare to another configuration option.
	 */

	@Override
	public int compareTo(AuthenticationSourceConfigurationOptionValue otherOption) {
		return displayName.compareToIgnoreCase(otherOption.displayName);
	}
	
}
