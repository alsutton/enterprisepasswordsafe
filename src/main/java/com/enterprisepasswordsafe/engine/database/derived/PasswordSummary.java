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

package com.enterprisepasswordsafe.engine.database.derived;

/**
 * Summary for a password, saves memory over using a full Password object. 
 */

public class PasswordSummary
        implements Comparable<PasswordSummary> {
	/**
	 * The ID of the password.
	 */
	
	private String passwordId;
	
	/**
	 * The string representation of a password.
	 */
	
	private String representation;
	
	/**
	 * Constructor. Stores details.
	 * 
	 * @param thePasswordId The ID of the password.
	 * @param theRepresentation The representation for the password.
	 */
	
	public PasswordSummary( String thePasswordId, String theRepresentation) {
		passwordId = thePasswordId;
		representation = theRepresentation;
	}
	
	/**
	 * Get the password ID.
	 * 
	 * @return The password ID.
	 */
	
	public String getId() {
		return passwordId;
	}
	
	/**
	 * Gets the string representation.
	 * 
	 * @return The string representation.
	 */
	
	public String getRepresentation() {
		return representation;
	}

	/**
	 * Compare this to another summary.
	 * 
	 * @param otherObject The other summary to compare to.
	 */
	public int compareTo(PasswordSummary otherSummary) {
		return passwordId.compareTo(otherSummary.passwordId);
	}
}
