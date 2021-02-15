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

import com.enterprisepasswordsafe.htmlunit.*;
import com.gargoylesoftware.htmlunit.TextPage;
import com.gargoylesoftware.htmlunit.html.*;
import org.junit.Test;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.List;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;

public final class ViewEventsTests extends EPSTestBase {

    @Test
    public void testViewingEvents()
        throws IOException {
        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EVENT_LOG_LINK).click();
        TestUtils.checkPageTitle(currentPage, "View Events");

        HtmlForm form = currentPage.getFormByName("EventReportOptions");
        String today = getCurrentDateAsStringInReportParameterFormat();
        TestUtils.setFormParameter(form, "startdate", today);
        TestUtils.setFormParameter(form, "enddate", today);
        currentPage = TestUtils.submit(form);

        TestUtils.checkPageTitle(currentPage, "View Events");
        TestUtils.checkForNoErrors(currentPage);
        TestUtils.logout(currentPage);
    }

    @Test
    public void testCSVExport()
        throws IOException {
        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EVENT_LOG_LINK).click();

        HtmlForm form = currentPage.getFormByName("EventReportOptions");
        String today = getCurrentDateAsStringInReportParameterFormat();
        TestUtils.setFormParameter(form, "startdate", today);
        TestUtils.setFormParameter(form, "enddate", today);
        TestUtils.setFormSelect(form, "export", "Y");

        List<HtmlElement> elements = form.getElementsByAttribute("button", "type", "submit");
        TextPage export = elements.get(0).click();
        String exportContent = export.getContent();
        assertNotNull(exportContent);
        assertFalse(exportContent.isEmpty());

        TestUtils.logout(currentPage);
    }

    private String getCurrentDateAsStringInReportParameterFormat() {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat("dd-MMM-yyyy");
        Calendar now = Calendar.getInstance();
        return simpleDateFormat.format(now.getTime());
    }
}
