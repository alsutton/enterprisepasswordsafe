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

package com.enterprisepasswordsafe.database.actions.search;

import com.enterprisepasswordsafe.database.Password;

/**
 * Interface implemented by all classes which represent test criteria.
 */
public final class UsernameContainsSearchTest implements SearchTest {
    /**
     * The username to test for.
     */

    private String testUsername;

    /**
     * Constructor. Store the username to test for.
     *
     * @param username
     *            The username to search for.
     */

    public UsernameContainsSearchTest(final String username) {
        testUsername = username.toLowerCase();
    }

    /**
     * Test to see if the password meets the criteria.
     *
     * @param password
     *            The password to test.
     *
     * @return true if the password matches, false if not.
     */

    public boolean matches(final Password password) {
    	try {
	        String username = password.getUsername();
	        return (username != null && username.toLowerCase().contains(testUsername));
    	} catch (Exception e) {
    		return false;
    	}
    }

}
