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
 * Class to handle the search for a notes field containing another string.
 */
public final class NotesContainsSearchTest implements SearchTest {
    /**
     * The string to test for.
     */

    private final String testSearchString;

    /**
     * Constructor. Store the string to test for.
     *
     * @param searchString
     *            The system to search for.
     */

    public NotesContainsSearchTest(final String searchString) {
        testSearchString = searchString.toLowerCase();
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
	        String notes = password.getNotes();
	        return (notes != null && notes.toLowerCase().contains(testSearchString));
    	} catch (Exception e) {
    		return false;
    	}
    }

}
