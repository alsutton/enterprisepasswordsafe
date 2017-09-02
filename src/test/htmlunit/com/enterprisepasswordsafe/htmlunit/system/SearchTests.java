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

import com.enterprisepasswordsafe.htmlunit.Constants;
import com.enterprisepasswordsafe.htmlunit.EPSTestBase;
import com.enterprisepasswordsafe.htmlunit.HtmlUnitUtils;
import com.enterprisepasswordsafe.htmlunit.PasswordTestUtils;
import com.enterprisepasswordsafe.htmlunit.TestUtils;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import java.io.IOException;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

/**
 * Test the search panel
 */
@RunWith(JUnit4.class)
public class SearchTests extends EPSTestBase {

    private static String runId;

    @BeforeClass
    public static void setup() throws IOException {
        runId = "searchTests_"+Long.toString(System.currentTimeMillis());

        WebClient webClient = HtmlUnitUtils.createWebClient();
        HtmlPage currentPage = TestUtils.loginAsAdmin(webClient);
        currentPage = PasswordTestUtils.createPassword(currentPage, runId);
        TestUtils.logout(currentPage);
        HtmlUnitUtils.closeWebClient(webClient);
    }

    @Test
    public void testNavigateToSearch() throws IOException {
        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.SEARCH_LINK).click();
        TestUtils.checkForNoErrors(currentPage);
        TestUtils.checkPageTitle(currentPage, "Password Search");
        TestUtils.logout(currentPage);
    }

    @Test
    public void testSearchUsername() throws IOException {
        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.SEARCH_LINK).click();
        HtmlForm form = currentPage.getFormByName("search_form");
        form.getInputByName("username").setValueAttribute(runId);
        currentPage = TestUtils.submit(form);
        assertThat(currentPage.getAnchorByText("pu" + runId + "@pl" + runId), is(notNullValue()));
        TestUtils.logout(currentPage);
    }

    @Test
    public void testSearchLocation() throws IOException {
        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.SEARCH_LINK).click();
        HtmlForm form = currentPage.getFormByName("search_form");
        form.getInputByName("system").setValueAttribute(runId);
        currentPage = TestUtils.submit(form);
        assertThat(currentPage.getAnchorByText("pu" + runId + "@pl" + runId), is(notNullValue()));
        TestUtils.logout(currentPage);
    }

    @Test
    public void testSearchNotes() throws IOException {
        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.SEARCH_LINK).click();
        HtmlForm form = currentPage.getFormByName("search_form");
        form.getInputByName("notes").setValueAttribute(runId);
        currentPage = TestUtils.submit(form);
        assertThat(currentPage.getAnchorByText("pu"+runId+"@pl"+runId), is(notNullValue()));
        TestUtils.logout(currentPage);
    }

    @Test
    public void testSeachUsernameFromExplorer() throws IOException {
        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        HtmlForm form = currentPage.getFormByName("search_form");
        form.getInputByName("username").setValueAttribute(runId);
        currentPage = TestUtils.submit(form);
        assertThat(currentPage.getAnchorByText("pu"+runId+"@pl"+runId), is(notNullValue()));
        TestUtils.logout(currentPage);
    }

    @Test
    public void testSeachLocationFromExplorer() throws IOException {
        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        HtmlForm form = currentPage.getFormByName("search_form");
        form.getInputByName("system").setValueAttribute(runId);
        currentPage = TestUtils.submit(form);
        assertThat(currentPage.getAnchorByText("pu"+runId+"@pl"+runId), is(notNullValue()));
        TestUtils.logout(currentPage);
    }
}
