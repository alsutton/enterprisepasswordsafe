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

import com.enterprisepasswordsafe.proguard.JavaBean;

/**
 * Summary information about a group, more memory efficient than a full Group object.
 */

public class GroupSummary
	implements Comparable<GroupSummary>, JavaBean {

    /**
     * The users id.
     */

    private final String id;

    /**
     * The users name.
     */

    private final String name;

    /**
     * Constructor. Stores relevant information.
     *
     * @param id The ID of the group.
     * @param name The name of the group.
     */
    public GroupSummary(final String id, final String name) {
        this.id = id;
        this.name = name;
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
     * @return The group name.
     */

    @Override
	public String toString() {
    	return getName();
    }

    /**
     * Compare to another user summary.
     */
	@Override
	public int compareTo(GroupSummary summary) {
		if( summary.id.equals(id) )
			return 0;
		return name.compareToIgnoreCase(summary.name);
	}
}
