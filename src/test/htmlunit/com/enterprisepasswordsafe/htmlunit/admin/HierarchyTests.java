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

import com.enterprisepasswordsafe.htmlunit.*;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import junit.framework.TestCase;
import org.junit.Test;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.Assert.assertThat;

/**
 * Base class for tests dealing with the created user.
 */
public class HierarchyTests extends EPSTestBase {

    /**
     * Test permission propagation.
     */
    @Test
    public void testPermissionPropagation( )
        throws IOException {
        String username =   "u_hicascade"+mRunId;
        String userId = UserTestUtils.createUser(username, "2");
        String nodeName = "n_hicascade"+mRunId;

        HtmlPage response = TestUtils.loginAsAdmin(wc);
        response = response.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        response = HierarchyNodeUtils.createSubnode(nodeName, response);
        response = response.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        response = response.getAnchorByText(nodeName).click();

        String password = "p_hicascade"+mRunId;
        response = PasswordTestUtils.createPassword(response, password);

        response = response.getAnchorByName("npath_Top Level").click();
        response = response.getAnchorByName("edithierarchy").click();
        response = response.getAnchorByName("eh_dpa").click();

        HtmlForm form = response.getFormByName("defaultsset");
        TestUtils.setFormRadioButton(form, "uperm_"+userId, "2");
        form.getInputByName("cascade").setChecked(true);
        response = TestUtils.submit(form);

        TestUtils.checkForNoErrors(response);

        response = response.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        response = response.getAnchorByText(nodeName).click();
        response = response.getAnchorByHref(Constants.WebUI.EDIT_HIERARCHY_LINK).click();
        response = response.getAnchorByName("eh_dpa").click();
        form = response.getFormByName("defaultsset");
        String value = form.getInputByName("uperm_"+userId).getValueAttribute();
        assertThat(value, is("2"));

        response = response.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        response = response.getAnchorByText("pu"+password).click();
        response = response.getAnchorByText("Alter access").click();
        form = response.getFormByName("editaccess");
        assertThat(form, is(notNullValue()));
        value = HtmlUnitUtils.getSelectedRadioValue(form, "u_" + userId + "_aRM");
        TestCase.assertNotNull("Password did not get cascaded permission for "+userId, value);

        TestUtils.logout(response);

        response = TestUtils.login(wc, username, UserTestUtils.DEFAULT_PASSWORD);
        response = response.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        response = response.getAnchorByText(nodeName).click();
        response = response.getAnchorByText("pu"+password).click();
        assertThat(response.getAnchorByText("Edit details"), is(notNullValue()));
        TestUtils.logout(response);
    }
}
