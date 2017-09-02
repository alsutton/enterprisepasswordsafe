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

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

/**
 * Utility methods related to the creation and manipulation of IP Zones
 */
public class NetworkZoneUtils {

    /**
     * Tests if a source exists on the authentication sources page.
     *
     * @param response A HtmlPage which should be on the Authentication Sources page.
     * @param name The name of the link.
     *
     * @return True if the source exists on the page, false if not.
     */
    public static boolean zoneExistsOnPage(HtmlPage response, String name) {
        return (response.getAnchorByName("edit_"+name) != null);
    }

    /**
     * Navigate to the page where a network zone can be added.
     *
     * @param wc The WebClient currently in use.
     */
    public static HtmlPage navigateToAddPage(WebClient wc)
        throws IOException {
        HtmlPage response = TestUtils.loginAsAdmin(wc);
        response = response.getAnchorByHref(Constants.WebUI.EDIT_IPZONES_LINK).click();
        response = response.getAnchorByText("Create New Network Zone").click();
        return response;
    }


    /**
     * Create an IP v4 zone.
     *
     * @param wc The WebClient currently in use.
     * @param zoneName The name of the zone to create.
     *
     * @return The ID of the created zone
     */
    public static String addIPV4Zone(final WebClient wc, final String zoneName)
            throws IOException {
        HtmlPage currentPage = navigateToAddPage(wc);

        HtmlForm form = currentPage.getFormByName("newzone");
        form.getInputByName("zonename").setValueAttribute(zoneName);
        TestUtils.setFormSelect(form, "ip.version", "4");
        form.getInputByName("start").setValueAttribute("192.168.0.0");
        form.getInputByName("end").setValueAttribute("192.168.0.255");
        currentPage = TestUtils.submit(form);

        TestUtils.checkForNoErrors(currentPage);
        TestUtils.checkPageTitle(currentPage, "Network Zones");

        assertThat(zoneExistsOnPage(currentPage, zoneName), is(true));

        HtmlAnchor editLink = currentPage.getAnchorByName("edit_" + zoneName);
        String link = editLink.getHrefAttribute();

        TestUtils.logout(currentPage);

        return link.substring(link.indexOf('=')+1);
    }


    /**
     * Create an IPv6 zone.
     *
     * @param wc The WebClient currently in use.
     * @param zoneName The name of the zone to create.
     *
     * @return The ID of the created zone
     */
    public static String addIPV6Zone(final WebClient wc, final String zoneName)
            throws IOException {
        HtmlPage currentPage = NetworkZoneUtils.navigateToAddPage(wc);

        HtmlForm form = currentPage.getFormByName("newzone");
        form.getInputByName("zonename").setValueAttribute(zoneName);
        TestUtils.setFormSelect(form, "ip.version", "6");
        form.getInputByName("start").setValueAttribute("00:11:22:33:44:55:66:77");
        form.getInputByName("end").setValueAttribute("11:22:33:44:55:66:77:88");
        currentPage = TestUtils.submit(form);

        TestUtils.checkForNoErrors(currentPage);
        TestUtils.checkPageTitle(currentPage, "Network Zones");

        assertThat(zoneExistsOnPage(currentPage, zoneName), is(true));

        HtmlAnchor editLink = currentPage.getAnchorByName("edit_" + zoneName);
        String link = editLink.getHrefAttribute();

        TestUtils.logout(currentPage);

        return link.substring(link.indexOf('=')+1);
    }
}
