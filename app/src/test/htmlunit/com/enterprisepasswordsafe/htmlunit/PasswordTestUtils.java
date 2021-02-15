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
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

import java.io.IOException;

import static org.hamcrest.CoreMatchers.is;
import static org.junit.Assert.assertThat;

/**
 * Base class for tests dealing with the created user.
 */
public final class PasswordTestUtils {

	/**
	 * The default password used in password creation.
	 */

	public static final String DEFAULT_PASSWORD = "abc123";

    /**
     * Private constructor to enforce singleton
     */
    private PasswordTestUtils() {
    	// Private Constructor
    }

    /**
     * Create a password.
     *
     * @return the name of the password.
     *
     * @throws IOException Thrown if there is a problem.
     */
    public static String createPassword(WebClient wc)
        throws IOException {

        String runId = Long.toString(System.currentTimeMillis());

        HtmlPage response = TestUtils.loginAsAdmin(wc);
        response = response.getAnchorByHref(Constants.WebUI.CREATE_PASSWORD_LINK).click();

        HtmlForm form = response.getFormByName("editform");
        response = populatePasswordForm(form, runId);

        TestUtils.checkStatusMessage(response, "The password was successfully created.");

        TestUtils.logout(response);

        return runId;
    }

    public static void loginAndCreatePasswordWithName(WebClient wc, String passwordName)
            throws IOException {
        HtmlPage response = TestUtils.loginAsAdmin(wc);
        response = response.getAnchorByHref(Constants.WebUI.CREATE_PASSWORD_LINK).click();

        HtmlForm form = response.getFormByName("editform");
        response = populatePasswordForm(form, passwordName);

        TestUtils.checkStatusMessage(response, "The password was successfully created.");

        TestUtils.logout(response);
    }

    /**
     * Create a password in the middle of a web conversation.
     *
     * @param page The page containing the password form.
     * @param runId The ID for this run, used to create the password name.
     */
    public static HtmlPage createPassword(final HtmlPage page, final String runId)
        throws IOException {
        HtmlPage currentPage = page.getAnchorByHref(Constants.WebUI.CREATE_PASSWORD_LINK).click();
        HtmlForm form = currentPage.getFormByName("editform");
        currentPage = populatePasswordForm(form, runId);
        return currentPage.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
    }

    /**
     * Create a password with a specific username and location
     *
     * @param page The page to navigate to the password location screen from.
     * @param username The username for the new password.
     * @param location The location for th new passw    
     */
    public static HtmlPage createPassword(final HtmlPage page, final String username,
                                          final String location)
            throws IOException {
        HtmlPage currentPage = page.getAnchorByHref(Constants.WebUI.CREATE_PASSWORD_LINK).click();
        HtmlForm form = currentPage.getFormByName("editform");
        form.getInputByName("username").setValueAttribute(username);
        form.getInputByName("password_1").setValueAttribute(DEFAULT_PASSWORD);
        form.getInputByName("password_2").setValueAttribute(DEFAULT_PASSWORD);
        form.getInputByName("location_text").setValueAttribute(location);
        form.getTextAreaByName("notes").setText("Unit testing test password");
        currentPage = TestUtils.submit(form);
        return currentPage.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
    }

    /**
     * Populate a password creation form. The username has "pu" prefixed to it, the location
     * as "pl" prefixed to it, and the notes has "Unit testing test password" prefixed.
     *
     * @param form The form to check.
     * @param uniqueID The ID of the password to create.
     *
     * @throws IOException Thrown if there is a problem.
     */
    public static HtmlPage populatePasswordForm(HtmlForm form, String uniqueID)
        throws IOException {
        form.getInputByName("username").setValueAttribute("pu"+uniqueID);
        form.getInputByName("password_1").setValueAttribute(DEFAULT_PASSWORD);
        form.getInputByName("password_2").setValueAttribute(DEFAULT_PASSWORD);
        form.getInputByName("location_text").setValueAttribute("pl" + uniqueID);
        form.getTextAreaByName("notes").setText("Unit testing test password "+uniqueID);
        return TestUtils.submit(form);
    }
}
