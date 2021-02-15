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
import com.enterprisepasswordsafe.htmlunit.NetworkZoneUtils;
import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.junit.Test;

import com.enterprisepasswordsafe.htmlunit.TestUtils;

import java.io.IOException;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.Assert.assertThat;

/**
 * Test suite for adding IP Zones
 */

public final class NetworkZoneTests extends EPSTestBase {

    /**
     * Test creating an IP v4 zone
     */
    @Test
    public void testAddIPV4Zone()
        throws IOException {
        String zoneName = "addipv4_" + System.currentTimeMillis();
        NetworkZoneUtils.addIPV4Zone(wc, zoneName);
    }

    /**
     * Test creating an IPv6 zone
     */
    @Test
    public void testAddIPV6Zone()
        throws IOException {
    	String zoneName = "addipv6_" + System.currentTimeMillis();
    	NetworkZoneUtils.addIPV6Zone(wc, zoneName);
    }

    /**
     * Test creating an IP v4 zone
     *
     * @throws Exception Thrown if there is a problem.
     */
    @Test
    public void testEditIPV4Zone()
        throws Exception {
    	String zoneName = "addipv4_ed_" + System.currentTimeMillis();
    	NetworkZoneUtils.addIPV4Zone(wc, zoneName);

        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EDIT_IPZONES_LINK).click();

        currentPage = changeParameter(currentPage, zoneName, "start", "10.0.0.1");
        currentPage = changeParameter(currentPage, zoneName, "end", "10.0.0.255");

        TestUtils.logout(currentPage);
    }

    /**
     * Test creating an IPv6 zone
     *
     * @throws Exception Thrown if there is a problem.
     */
    @Test
    public void testEditIPV6Zone()
        throws Exception {
    	String zoneName = "editipv6_" + System.currentTimeMillis();
    	NetworkZoneUtils.addIPV6Zone(wc, zoneName);

        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EDIT_IPZONES_LINK).click();

        currentPage = changeParameter(currentPage, zoneName, "start", "12:1:2:3:4:5:6:21");
        currentPage = changeParameter(currentPage, zoneName, "end", "12:1:2:3:4:5:6:f0dd");

        TestUtils.logout(currentPage);
    }

    /**
     * Change a parameter to a set value and back.
     */
    private HtmlPage changeParameter(final HtmlPage response,
    		final String zoneName, final String parameterName,
            final String paramValue)
    	throws Exception {
		HtmlAnchor link = response.getAnchorByName("edit_"+zoneName);
        assertThat(link, notNullValue());
		HtmlPage htmlPage = link.click();

		HtmlForm form = htmlPage.getFormByName("editzone");
        HtmlInput param = form.getInputByName(parameterName);
		String currentValue = param.getValueAttribute();
        param.setValueAttribute(paramValue);
        htmlPage = TestUtils.submit(form);

		TestUtils.checkForNoErrors(htmlPage);
		TestUtils.checkPageTitle(htmlPage, "Network Zones");
		TestUtils.checkStatusMessage(htmlPage, "The zone has been updated.");

		link = htmlPage.getAnchorByName("edit_"+zoneName);
        assertThat(link, notNullValue());
        htmlPage = link.click();

		form = htmlPage.getFormByName("editzone");
        param = form.getInputByName(parameterName);
		assertThat(param.getValueAttribute(), is(paramValue));
		param.setValueAttribute(currentValue);
		htmlPage = TestUtils.submit(form);

		TestUtils.checkForNoErrors(htmlPage);
		TestUtils.checkPageTitle(htmlPage, "Network Zones");
		TestUtils.checkStatusMessage(htmlPage, "The zone has been updated.");

		return htmlPage;
    }

}
