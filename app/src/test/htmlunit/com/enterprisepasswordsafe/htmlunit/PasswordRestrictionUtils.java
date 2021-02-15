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
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.Assert.assertThat;

/**
 * Class holding the password restrictions utilities for tests.
 */

public final class PasswordRestrictionUtils {

	/**
	 * Private constructor. Avoids  instanciation.
	 */

	private PasswordRestrictionUtils() {
		super();
	}

	/**
	 * Create a password restriction
	 */

	public static String createPasswordRestriction(String name)
		throws IOException {
        WebClient wc = new WebClient();

        HtmlPage page = TestUtils.loginAsAdmin(wc);

        page = page.getAnchorByHref(Constants.WebUI.PASSWORD_RESTRICTIONS_LINK).click();
        TestUtils.checkForNoErrors(page);
        TestUtils.checkPageTitle(page, "Password Restrictions");

        page = page.getAnchorByHref(Constants.WebUI.PASSWORD_RESTRICTIONS_ADD_STAGE1_LINK).click();
        TestUtils.checkForNoErrors(page);
        TestUtils.checkPageTitle(page, "Add Password Restriction");

        HtmlForm form = page.getFormByName("addform");
        form.getInputByName("name").setValueAttribute(name);
        form.getInputByName("size_min").setValueAttribute("1");
        form.getInputByName("size_max").setValueAttribute("8");
        form.getInputByName("upper_min").setValueAttribute("1");
        form.getInputByName("lower_min").setValueAttribute("1");
        form.getInputByName("numeric_min").setValueAttribute("1");
        form.getInputByName("special_min").setValueAttribute("1");
        form.getInputByName("chars_special").setValueAttribute("#!.");
        page = TestUtils.submit(form);

        TestUtils.checkForNoErrors(page);
        TestUtils.checkPageTitle(page, "Password Restrictions");

        HtmlAnchor link = page.getAnchorByName("edit_" + name);
        assertThat(link, is(notNullValue()));
        String linkAddress = link.getHrefAttribute();
        String id = linkAddress.substring( linkAddress.indexOf("id=") + 3);
        assertThat(id, is(notNullValue()));

        TestUtils.logout(page);
        wc.closeAllWindows();

        return id;
	}
}
