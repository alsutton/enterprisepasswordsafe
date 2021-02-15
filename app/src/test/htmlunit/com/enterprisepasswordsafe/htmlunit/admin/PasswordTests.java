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

package com.enterprisepasswordsafe.htmlunit.admin;

import com.enterprisepasswordsafe.htmlunit.Constants;
import com.enterprisepasswordsafe.htmlunit.EPSTestBase;
import com.enterprisepasswordsafe.htmlunit.PasswordTestUtils;
import com.enterprisepasswordsafe.htmlunit.TestUtils;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

/**
 * Tests on password activities which are performed as an admin.
 */
@RunWith(JUnit4.class)
public class PasswordTests extends EPSTestBase {

    /**
     * Test a password is created with the right information
     */

    @Test
    public void testPasswordIsCreatedCorrectly() throws IOException {
        String runId = Long.toString(System.currentTimeMillis());

        HtmlPage response = TestUtils.loginAsAdmin(wc);
        response = response.getAnchorByHref(Constants.WebUI.CREATE_PASSWORD_LINK).click();

        HtmlForm form = response.getFormByName("editform");
        response = PasswordTestUtils.populatePasswordForm(form, runId);

        TestUtils.checkStatusMessage(response, "The password was successfully created.");

        assertThat(TestUtils.getSpanText(response, "username"), is("pu"+runId));
        assertThat(TestUtils.getSpanText(response, "system"), is("pl" + runId));

        TestUtils.logout(response);
    }
}
