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

package com.enterprisepasswordsafe.database.derived;

import org.immutables.value.Value;

/**
 * Summary information about a user, more memory efficient than a full User object.
 */
@Value.Immutable
public abstract class AbstractUserSummary implements Comparable<AbstractUserSummary> {
	public abstract String getId();
	public abstract String getName();
	public abstract String getFullName();

    /**
     * Get the string representation of the user.
     * 
     * @return The representation "username (full name)".
     */
    @Override
    public String toString() {
    	StringBuilder buffer = new StringBuilder();
    	buffer.append(getName());
    	if( getFullName() != null ) {
    		buffer.append(" (");
    		buffer.append(getFullName());
    		buffer.append(')');
    	}
    	
    	return buffer.toString();
    }

    @Override
	public int compareTo(AbstractUserSummary summary) {
		if( summary.getId().equals(getId()) )
			return 0;
		return getName().compareToIgnoreCase(summary.getName());
	}
}
