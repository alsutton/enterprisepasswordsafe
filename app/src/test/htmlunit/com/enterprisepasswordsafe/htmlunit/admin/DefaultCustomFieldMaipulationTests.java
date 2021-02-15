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

import java.io.IOException;

import com.enterprisepasswordsafe.htmlunit.Constants;
import com.gargoylesoftware.htmlunit.ElementNotFoundException;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.enterprisepasswordsafe.htmlunit.EPSTestBase;
import com.enterprisepasswordsafe.htmlunit.TestUtils;
import org.junit.Test;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;

/**
 * Test suite for adding IP Zones
 */

public class DefaultCustomFieldMaipulationTests extends EPSTestBase {

    /**
     * Test creating an IP v4 zone
     */
    @Test
    public void testAddCustomField()
        throws IOException {
    	String fieldName = "Cf_" + System.currentTimeMillis();

    	HtmlPage response = TestUtils.loginAsAdmin(wc);
    	response = response.getAnchorByHref(Constants.WebUI.CUSTOM_FIELDS_LINK).click();

    	HtmlForm form = response.getFormByName("customfields");
    	response = TestUtils.submit(form,"action","addButton");

    	TestUtils.checkForNoErrors(response);
    	TestUtils.checkStatusMessage(response, "The custom fields have been updated");
    	TestUtils.checkPageTitle(response, "Default custom fields");

    	form = response.getFormByName("customfields");
        form.getInputByName("fn_0").setValueAttribute(fieldName);
        form.getInputByName("fv_0").setValueAttribute("X"+fieldName);
    	response = TestUtils.submit(form,"action","storeButton");

    	TestUtils.checkForNoErrors(response);
    	TestUtils.checkStatusMessage(response, "The custom fields have been updated");
    	TestUtils.checkPageTitle(response, "Password Hierarchy");

    	response = response.getAnchorByHref(Constants.WebUI.CUSTOM_FIELDS_LINK).click();

    	form = response.getFormByName("customfields");
        assertThat(form.getInputByName("fn_0").getValueAttribute(), is(fieldName));
        assertThat(form.getInputByName("fv_0").getValueAttribute(), is("X" + fieldName));
        form.getInputByName("fdel_0").setChecked(true);
    	response = TestUtils.submit(form,"action","storeButton");

    	TestUtils.checkForNoErrors(response);
    	TestUtils.checkStatusMessage(response, "The custom fields have been updated");
    	TestUtils.checkPageTitle(response, "Password Hierarchy");

    	response = response.getAnchorByHref(Constants.WebUI.CUSTOM_FIELDS_LINK).click();

    	form = response.getFormByName("customfields");
        try {
            assertThat(form.getInputByName("fn_0"), is(nullValue()));
        } catch(ElementNotFoundException enfe) {
            // This is correct.
        }

    	TestUtils.logout(response);
    }
}
