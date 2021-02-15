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

import com.enterprisepasswordsafe.htmlunit.*;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

public class PersonalPasswordsTests extends EPSTestBase {

    private static String mUsername;

    @Before
    public void setup() throws IOException {
        mUsername = "personal_folder_" + mRunId;
        UserTestUtils.createUser(mUsername,"2");
    }

    @Test
    public void testAccessPersonalFolder()
            throws IOException {
        HtmlPage currentPage = goToPersonalPasswordPage();
        TestUtils.checkForNoErrors(currentPage);
        TestUtils.logout(currentPage);
    }

    @Test
    public void testCreateInPersonalFolder()
            throws IOException {
        HtmlPage currentPage = goToPersonalPasswordPage();
        currentPage = clickOnLinkWithName(currentPage, "createpassword");

        HtmlForm form = currentPage.getFormByName("editform");
        currentPage = PasswordTestUtils.populatePasswordForm(form, mUsername+"_create");
        TestUtils.checkStatusMessage(currentPage, "The password was successfully created.");
        TestUtils.checkForNoErrors(currentPage);

        checkLinkWithNameExists(currentPage, "delete_pu"+mUsername+"_create@pl"+mUsername+"_create");

        TestUtils.logout(currentPage);
    }

    @Test
    public void testViewInPersonalFolder()
            throws IOException {
        HtmlPage currentPage = goToPersonalPasswordPage();
        currentPage = clickOnLinkWithName(currentPage, "createpassword");

        HtmlForm form = currentPage.getFormByName("editform");
        currentPage = PasswordTestUtils.populatePasswordForm(form, mUsername+"_view");

        currentPage = clickOnLinkWithName(currentPage, "edit_pu"+mUsername+"_view@pl"+mUsername+"_view");
        assertThat(getUsernameFromPage(currentPage), is("pu"+mUsername+"_view"));
        assertThat(getSystemFromPage(currentPage), is("pl"+mUsername+"_view"));

        checkLinkWithTextExists(currentPage, "Edit details");

        checkActionButtonsArentPresent(currentPage);

        TestUtils.logout(currentPage);
    }

    @Test
    public void testEditInPersonalFolder()
            throws IOException {
        HtmlPage currentPage = goToPersonalPasswordPage();
        currentPage = currentPage.getAnchorByName("createpassword").click();

        HtmlForm form = currentPage.getFormByName("editform");
        currentPage = PasswordTestUtils.populatePasswordForm(form, mUsername+"_edit");
        currentPage = clickOnLinkWithName(currentPage, "edit_pu"+mUsername+"_edit@pl"+mUsername+"_edit");
        currentPage = clickOnLinkWithText(currentPage, "Edit details");

        form = currentPage.getFormByName("editform");
        form.getInputByName("username").setValueAttribute("pu"+mUsername+"_Modded");
        currentPage = TestUtils.submit(form);

        TestUtils.checkPageTitle(currentPage,"View Password");
        TestUtils.checkStatusMessage(currentPage, "The password was successfully changed.");
        TestUtils.checkForNoErrors(currentPage);

        assertThat(getUsernameFromPage(currentPage), is("pu"+mUsername+"_Modded"));
        checkLinkWithTextExists(currentPage, "Edit details");

        checkActionButtonsArentPresent(currentPage);

        TestUtils.logout(currentPage);
    }

    @Test
    public void testDeleteInPersonalFolder()
            throws IOException {
        HtmlPage currentPage = goToPersonalPasswordPage();
        currentPage = clickOnLinkWithName(currentPage, "createpassword");

        HtmlForm form = currentPage.getFormByName("editform");
        currentPage = PasswordTestUtils.populatePasswordForm(form, mUsername+"_del");

        currentPage = clickOnLinkWithName(currentPage, "delete_pu" + mUsername + "_del@pl" + mUsername + "_del");

        TestUtils.checkStatusMessage(currentPage, "The password has been deleted.");

        checkLinkWithNameDoesntExist(currentPage, "delete_pu" + mUsername + "_del@pl" + mUsername + "_del");

        TestUtils.logout(currentPage);
    }

    private HtmlPage goToPersonalPasswordPage()
        throws IOException {
        HtmlPage currentPage = TestUtils.login(wc, mUsername, UserTestUtils.DEFAULT_PASSWORD);
        return clickOnLinkWithHref(currentPage, Constants.WebUI.PERSONAL_NODE_VIEW_LINK);
    }

    private void checkActionButtonsArentPresent(HtmlPage currentPage) {
        checkLinkWithTextDoesntExist(currentPage, "Alter access");
        checkLinkWithTextDoesntExist(currentPage, "Alter integration");
        checkLinkWithTextDoesntExist(currentPage, "View History");
    }

    private String getUsernameFromPage(HtmlPage currentPage) {
        return getContentsOfSpan(currentPage, "username");
    }

    private String getSystemFromPage(HtmlPage currentPage) {
        return getContentsOfSpan(currentPage, "system");
    }
}
