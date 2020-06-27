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
 * Summary information about a user, more memory efficient than a full User object.
 */
public class UserSummary
	implements Comparable<UserSummary> {

    /**
     * The users id.
     */

    private String id;

    /**
     * The users name.
     */

    private String name;

    /**
     * The users full name.
     */

    private String fullName;

    /**
     * Constructor. Stores relevant information.
     *
     * @param newId The ID to store.
     * @param newName The name to store.
     * @param newFullName The full name to store.
     */
    public UserSummary(final String newId, final String newName, final String newFullName) {
        this(newName, newFullName);
        id = newId;
    }

    public UserSummary(final String newName, final String newFullName) {
        name = newName;
        fullName = newFullName;
    }

    /**
     * Get the full name.
     *
     * @return Returns the fullName.
     */
    public String getFullName() {
        return fullName;
    }

    /**
     * Get the Id.
     *
     * @return Returns the id.
     */
    public String getId() {
        return id;
    }

    /**
     * Get the name.
     *
     * @return Returns the name.
     */
    public String getName() {
        return name;
    }
    
    /**
     * Get the string representation of the user.
     * 
     * @return The representation "username (full name)".
     */
    
    public String toString() {
    	StringBuffer buffer = new StringBuffer();
    	buffer.append(getName());
    	if( getFullName() != null ) {
    		buffer.append(" (");
    		buffer.append(getFullName());
    		buffer.append(')');
    	}
    	
    	return buffer.toString();
    }

    /**
     * Compare to another user summary.
     */
	public int compareTo(UserSummary summary) {
		if( summary.id.equals(id) )
			return 0;
		return name.compareToIgnoreCase(summary.name);
	}
}
