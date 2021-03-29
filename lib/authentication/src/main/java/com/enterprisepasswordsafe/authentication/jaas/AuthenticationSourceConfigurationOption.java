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

import java.util.Set;

/**
 * Class representing a configuration object for an authentication source.
 */
public class AuthenticationSourceConfigurationOption
	implements Comparable<AuthenticationSourceConfigurationOption> {

	/**
	 * The types of configuration.
	 */
	
	public static final String	TEXT_INPUT_BOX = "t",
								PASSWORD_INPUT_BOX = "p",
								RADIO_BOX = "r",
								SELECT_BOX = "s";
	
	/**
	 * The order to display this option on screen.
	 */
	
	private final int displayOrder;
	
	/**
	 * The name to show the user.
	 */
	
	private final String displayName;
	
	/**
	 * The internal name.
	 */
	
	private final String internalName;
	
	/**
	 * The type of option
	 */
	
	private final String optionType;
	
	/**
	 * The possible values
	 */
	
	private final Set<AuthenticationSourceConfigurationOptionValue> values;

	/**
	 * The value for this parameter
	 */
	
	private String value;
	
	/**
	 * Constructor. Stores values passed.
	 */
	
	public AuthenticationSourceConfigurationOption(
			final int newDisplayOrder,
			final String newDisplayName,
			final String newInternalName,
			final String newOptionType,
			final Set<AuthenticationSourceConfigurationOptionValue> newValues,
			final String newValue) {
		displayOrder = newDisplayOrder;
		displayName = newDisplayName;
		internalName = newInternalName;
		optionType = newOptionType;
		values = newValues;
		value = newValue;
	}
	
	public String getDisplayName() {
		return displayName;
	}

	public String getInternalName() {
		return internalName;
	}

	public String getOptionType() {
		return optionType;
	}

	public Set<AuthenticationSourceConfigurationOptionValue> getValues() {
		return values;
	}
	
	/**
	 * Compare to another configuration option.
	 */

	@Override
	public int compareTo(AuthenticationSourceConfigurationOption otherOption) {
		return displayOrder - otherOption.displayOrder;  
	}

	/**
	 * Set the current value for this option.
	 * 
	 * @param newValue The value to set.
	 */
	
	public void setValue(String newValue) {
		value = newValue;
	}
	
	/**
	 * Get the current value for the option.
	 * 
	 * @return The current value.
	 */
	public String getValue() {
		return value;
	}	
}
