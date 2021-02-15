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

import com.gargoylesoftware.htmlunit.ElementNotFoundException;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.enterprisepasswordsafe.htmlunit.EPSTestBase;
import com.enterprisepasswordsafe.htmlunit.TestUtils;
import org.junit.Ignore;
import org.junit.Test;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;

public class IntegrationModuleTests extends EPSTestBase {

    /**
     * Test accessing the protected areas without logging in.
     *
     * TODO: Re-enable when SSH plugin has been updated.
     */
    @Test
    @Ignore
    public void testInstallingSSHIntegrator()
        throws IOException {
        HtmlPage response = TestUtils.loginAsAdmin(wc);

        response = response.getAnchorByHref("/admin/IntegrationModules").click();
        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Integration Modules");

        response = response.getAnchorByText("Install new integration module").click();
        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Install Integration Module");

        HtmlForm form = response.getFormByName("installform");
        form.getInputByName("im.name").setValueAttribute("SSHIntegrator");
        response = TestUtils.submit(form);
        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Integration Modules");

        response = response.getAnchorByText("Uninstall").click();
        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Integration Modules");

        try {
            assertThat(response.getAnchorByText("Uninstall"), is(nullValue()));
        } catch(ElementNotFoundException e) {
            // This is what should be thrown
        }

        TestUtils.logout(response);
    }
}
