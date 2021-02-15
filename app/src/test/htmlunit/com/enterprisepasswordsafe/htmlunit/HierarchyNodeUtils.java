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

import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.junit.Assert;


public class HierarchyNodeUtils {

    /**
     * Create a subnode and return it's ID.
     *
     * @throws IOException
     */

    public static HtmlPage createSubnode(final String nodeName, final HtmlPage page)
    	throws IOException {
        HtmlPage currentPage = page.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EDIT_HIERARCHY_LINK).click();
        currentPage.getAnchorByText("Add Folder").click();

        HtmlForm newNameForm = currentPage.getFormByName("addfolder");
        newNameForm.getInputByName("name").setValueAttribute(nodeName);
        currentPage = TestUtils.submit(newNameForm);

        TestUtils.checkForNoErrors(currentPage);
        TestUtils.checkStatusMessage(currentPage, "The node has been created.");

        return currentPage;
    }

}
