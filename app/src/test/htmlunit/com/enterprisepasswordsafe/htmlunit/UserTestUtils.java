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

import com.gargoylesoftware.htmlunit.ElementNotFoundException;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlOption;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.junit.Ignore;

import java.io.IOException;
import java.util.List;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

/**
 * Base class for tests dealing with the created user.
 */
@Ignore
public final class UserTestUtils {

	public static final String DEFAULT_PASSWORD = "AAAaaa123";

    private UserTestUtils( ) {
    	// Private constructor to enforce singleton.
    }

    /**
     * Create a user.
     *
     * @param username The username to use.
     * @param userType The type of user to create.
     */

    public static String createUser( String username, String userType )
        throws IOException {
        return createUser(username, userType, false);
    }

    /**
     * Create a user.
     *
     * @param username The username to use.
     * @param userType The type the user should be created as.
     * @param isNonViewing Whether or not the user should be created as a non-viewing user.
     */

    public static String createUser( String username, String userType, boolean isNonViewing )
        throws IOException {
        WebClient wc = new WebClient();

        HtmlPage page = TestUtils.loginAsAdmin(wc);
        page = page.getAnchorByHref(Constants.WebUI.USERS_VIEW_LINK).click();
        page = page.getAnchorByHref(Constants.WebUI.USERS_EDIT_LINK).click();

        TestUtils.checkPageTitle(page, "User Profile");

        HtmlForm form = page.getFormByName("userdetails");

        form.getInputByName("fn").setValueAttribute("HTTPUnitUser_"+username);
        form.getInputByName("username").setValueAttribute(username);
        form.getInputByName("em").setValueAttribute(username+"@carbonsecurity.co.uk");
        form.getInputByName("password1").setValueAttribute(DEFAULT_PASSWORD);
        form.getInputByName("password2").setValueAttribute(DEFAULT_PASSWORD);
        page = TestUtils.submit(form);

        TestUtils.checkStatusMessage(page, "The profile has been created.");

        form = page.getFormByName("userdetails");
        String userId = form.getInputByName("userId").getValueAttribute();
        UserTestUtils.verifyUserForm(form, username);
        form.getInputByName("password1").setValueAttribute(DEFAULT_PASSWORD);
        form.getInputByName("password2").setValueAttribute(DEFAULT_PASSWORD);
        TestUtils.setFormSelect(form, "user_type", userType);
        TestUtils.setFormSelect(form, "noview", isNonViewing ? "Y" : "N");
        page = TestUtils.submit(form);

        TestUtils.logout(page);
        wc.closeAllWindows();

        return userId;
    }

    /**
     * Create a multiple users.
     *
     * @param userIds the Array to fill with the user IDs.
     * @param usernames The names of the user to create.
     * @param userType They type of user to create.
     */

    public static void createMultipleUsers( String[] userIds, String[] usernames,
    		String userType)
        throws IOException {
        WebClient wc = new WebClient();
        HtmlPage response = TestUtils.loginAsAdmin(wc);
        response = createMultipleUsers( response, userIds, usernames, userType);
        TestUtils.logout(response);
        wc.closeAllWindows();
    }

    /**
     * Create a multiple users.
     *
     * @param page The page to navigate from to create the user.
     * @param userIds the Array to fill with the user IDs.
     * @param usernames The names of the user to create.
     * @param userType The type of user to create.
     */

    public static HtmlPage createMultipleUsers(final HtmlPage page,
            final String[] userIds, final String[] usernames,  final String userType )
        throws IOException {

    	HtmlPage currentPage = page;
        for( int i = 0 ; i < usernames.length ; i++) {
            currentPage = page.getAnchorByHref(Constants.WebUI.USERS_VIEW_LINK).click();
            currentPage = currentPage.getAnchorByHref(Constants.WebUI.USERS_EDIT_LINK).click();

	        HtmlForm form = currentPage.getFormByName("userdetails");
	        form.getInputByName("fn").setValueAttribute("HTTPUnitUser_"+usernames[i]);
	        form.getInputByName("username").setValueAttribute(usernames[i]);
	        form.getInputByName("em").setValueAttribute(usernames[i] + "@funkyandroid.com");
	        form.getInputByName("password1").setValueAttribute(DEFAULT_PASSWORD);
	        form.getInputByName("password2").setValueAttribute(DEFAULT_PASSWORD);
            currentPage = TestUtils.submit(form);

	        TestUtils.checkForNoErrors(currentPage);
	        form = currentPage.getFormByName("userdetails");
	        userIds[i] = form.getInputByName("userId").getValueAttribute();
	        UserTestUtils.verifyUserForm(form, usernames[i]);
	        form.getInputByName("password1").setValueAttribute(DEFAULT_PASSWORD);
	        form.getInputByName("password2").setValueAttribute(DEFAULT_PASSWORD);
	        form.getSelectByName("user_type").setSelectedAttribute(userType, true);
	        currentPage = TestUtils.submit(form);
        }

        return currentPage;
    }

    /**
     * Test if a user exists
     *
     * @param userId The ID of the user to check for.
     *
     * @return true if the user exists, false if not.
     */

    public static boolean userExists( String userId )
        throws IOException {
    	WebClient wc = new WebClient();
        HtmlPage page = TestUtils.loginAsAdmin(wc);
        page = page.getAnchorByHref(Constants.WebUI.USERS_VIEW_LINK).click();
        boolean exists = false;
        try {
            exists = (page.getAnchorByHref(Constants.WebUI.USERS_EDIT_LINK+"?userId="+userId) != null);
        } catch (ElementNotFoundException e) {
            // Do nothing, exists will alreadt be false;
        }
	    TestUtils.logout(page);
        wc.closeAllWindows();
	    return exists;
    }

    /**
     * Test accessing the protected areas without logging in.
     *
     * @param form The form to check.
     * @param userName The username being used for this test set.
     */
    public static void verifyUserForm(HtmlForm form, String userName) {
        String text = form.getInputByName("username").getValueAttribute();
        assertThat(text, is(userName));

        text = form.getInputByName("fn").getValueAttribute();
        assertThat(text, is("HTTPUnitUser_"+userName));

        text = form.getInputByName("em").getValueAttribute();
        assertThat(text, is(userName + "@funkyandroid.com"));

        List<HtmlOption> selectedOptions = form.getSelectByName("auth_source").getSelectedOptions();
        assertThat(selectedOptions.size(), is(1));
        assertThat(selectedOptions.get(0).getValueAttribute(), is("0"));

        text = form.getSelectByName("user_type").getDefaultValue();
        assertThat(text, is("2"));

        text = form.getSelectByName("user_enabled").getDefaultValue();
        assertThat(text, is("Y"));

        text = form.getInputByName("password1").getValueAttribute();
        assertThat(text, is(""));

        text = form.getInputByName("password2").getValueAttribute();
        assertThat(text, is(""));
    }
}
