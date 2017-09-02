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

import java.io.IOException;

import com.gargoylesoftware.htmlunit.ElementNotFoundException;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.junit.After;
import org.junit.Before;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.junit.Assert.assertThat;

public abstract class EPSTestBase {

    protected WebClient wc;

    protected String mRunId;

    @Before
    public void setUp() throws IOException {
        wc = HtmlUnitUtils.createWebClient();
        mRunId = Long.toHexString(System.currentTimeMillis());
    }

    @After
    public void tearDown() {
        HtmlUnitUtils.closeWebClient(wc);
    }

    protected void checkLinkWithNameExists(final HtmlPage currentPage, final String name) {
        assertThat(currentPage.getAnchorByName(name), is(notNullValue()));
    }

    protected void checkLinkWithNameDoesntExist(final HtmlPage currentPage, final String name) {
        try {
            assertThat(currentPage.getAnchorByName(name), is(nullValue()));
        } catch(ElementNotFoundException e) {
            // This is OK, we should not find the element.
        }
    }

    protected HtmlPage clickOnLinkWithName(HtmlPage currentPage, String name)
            throws IOException {
        return currentPage.getAnchorByName(name).click();
    }

    protected HtmlPage clickOnLinkWithText(HtmlPage currentPage, String text)
            throws IOException {
        return currentPage.getAnchorByText(text).click();
    }

    protected void checkLinkWithTextExists(final HtmlPage currentPage, final String text) {
        assertThat(currentPage.getAnchorByText(text), is(notNullValue()));
    }

    protected void checkLinkWithTextDoesntExist(final HtmlPage currentPage, final String buttonText) {
        try {
            assertThat(currentPage.getAnchorByText(buttonText), is(nullValue()));
        } catch(ElementNotFoundException e) {
            // This is OK, we should not find the element.
        }
    }

    protected HtmlPage clickOnLinkWithHref(HtmlPage currentPage, String targetUrl)
            throws IOException {
        return currentPage.getAnchorByHref(targetUrl).click();
    }

    protected String getContentsOfSpan(final HtmlPage currentPage, final String spanName) {
        return currentPage.getElementById(spanName).getTextContent().trim();
    }
}
