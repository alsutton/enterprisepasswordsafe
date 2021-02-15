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

package com.enterprisepasswordsafe.htmlunit;

import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

import java.io.IOException;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNot.not;
import static org.junit.Assert.assertThat;

/**
 * Base class for tests dealing with the created user.
 */
public final class AuthSourceTestUtils {

    private AuthSourceTestUtils( ) {
    	// Private constructor to enforce singleton.
    }

    /**
     * Create a auth source.
     *
     * @param name The name to use for the source.
     */

    public static String createAuthSource( String name )
        throws IOException {
        WebClient wc = new WebClient();

        HtmlPage page = TestUtils.loginAsAdmin(wc);
        page = page.getAnchorByHref(Constants.WebUI.AUTH_SOURCES_LINK).click();
        page = page.getAnchorByText("Create New Source").click();
        page = page.getAnchorByText("Active Directory (using Domains)").click();

        HtmlForm form = page.getFormByName("configure");
        form.getInputByName("name").setValueAttribute(name);
        form.getInputByName("auth_ad.domain").setValueAttribute("TESTDOMAIN");
        form.getInputByName("auth_ad.ldaps").setValueAttribute("N");
        form.getInputByName("auth_ad.domaincontroller").setValueAttribute("TESTDC");
        page = TestUtils.submit(form);

        TestUtils.checkForNoErrors(page);
        TestUtils.checkPageTitle(page, "Authentication Sources");

        HtmlAnchor editLink = page.getAnchorByName("edit_"+name);
        String href = editLink.getHrefAttribute();
        int idx = href.indexOf("id=");
        assertThat(idx, is(not(-1)));
        String id = href.substring(idx+3);

        TestUtils.logout(page);
        wc.closeAllWindows();

        return id;
    }
}
