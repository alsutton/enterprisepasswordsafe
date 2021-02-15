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

package com.enterprisepasswordsafe.htmlunit.system;

import com.enterprisepasswordsafe.htmlunit.*;
import com.gargoylesoftware.htmlunit.ElementNotFoundException;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

public class NonViewingUserTests extends EPSTestBase {

    /**
     * Test logging in and logging out.
     *
     * @throws Exception Thrown if there is a problem.
     */
    @Test
    public void testNonViewingUser()
        throws Exception {
        String name = "pu"+PasswordTestUtils.createPassword(wc);

        String username = "nvu_"+System.currentTimeMillis();
        UserTestUtils.createUser(username, "0", true);

        // Can the main admin see the password
        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        assertThat(currentPage.getAnchorByText(name), is(not(nullValue())));
        TestUtils.logout(currentPage);

        // Can the new admin not see it.
        currentPage = TestUtils.login(wc, username, UserTestUtils.DEFAULT_PASSWORD);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        try {
            assertThat(currentPage.getAnchorByText(name), is(nullValue()));
        } catch(ElementNotFoundException e) {
            // This is OK, we expect not to find the element
        }
        TestUtils.logout(currentPage);
    }
}
