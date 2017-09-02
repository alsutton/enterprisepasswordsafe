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

import java.io.IOException;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.html.DomElement;
import com.gargoylesoftware.htmlunit.html.DomNodeList;
import com.gargoylesoftware.htmlunit.html.HtmlElement;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.enterprisepasswordsafe.htmlunit.Constants;
import com.enterprisepasswordsafe.htmlunit.EPSTestBase;
import com.enterprisepasswordsafe.htmlunit.TestUtils;
import com.enterprisepasswordsafe.htmlunit.UserTestUtils;
import org.junit.Test;

import javax.servlet.http.HttpServletResponse;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

public final class LoginPasswordTests extends EPSTestBase {

    /**
     * Test changing the users login password.
     */
    @Test
    public void testSuccessfulChange()
        throws IOException {
        HtmlPage response = TestUtils.loginAsAdmin(wc);

        response = response.getAnchorByHref(Constants.WebUI.PROFILE_LINK).click();
        assertThat(response.getUrl().toString(), is(Constants.WebUI.PROFILE_SERVLET));
        Iterable<HtmlElement> iterable = response.getDocumentElement().getHtmlElementDescendants();
        for(HtmlElement element : iterable) {
            Logger.getAnonymousLogger().log(Level.SEVERE, element.toString()+":"+element.getTextContent());
        }

        HtmlForm form = response.getFormByName("passwordchange");
        TestUtils.setFormParameter(form, "currentpassword", "admin");
        TestUtils.setFormParameter(form, "password1", "newadmin");
        TestUtils.setFormParameter(form, "password2", "newadmin");
        response = TestUtils.submit(form);

        TestUtils.checkStatusMessage(response, "Your password was updated");

        TestUtils.logout(response);

        response = TestUtils.login(wc, "admin", "newadmin");

        response = response.getAnchorByHref(Constants.WebUI.PROFILE_LINK).click();

        form = response.getFormByName("passwordchange");
        TestUtils.setFormParameter(form, "currentpassword", "newadmin");
        TestUtils.setFormParameter(form, "password1", "admin");
        TestUtils.setFormParameter(form, "password2", "admin");
        response = TestUtils.submit(form);

        TestUtils.checkStatusMessage(response, "Your password was updated");

        TestUtils.logout(response);

        response = TestUtils.login(wc, "admin", "admin");
        TestUtils.logout(response);
    }


    /**
     * Test accessing the admin area without logging in.
     */
    @Test
    public void testAccessAdminAreaWithoutAuthorisation()
        throws IOException {
    	HtmlPage response = wc.getPage(Constants.WebUI.ADMIN_URL);
        assertThat(response.getUrl().toString(), is(Constants.WebUI.LOGIN_SERVLET));
    }

    /**
     * Test accessing the subadmin area without logging in.
     */
    @Test
    public void testAccessSubadminAreaWithoutAuthorisation()
        throws IOException {
    	HtmlPage response = wc.getPage(Constants.WebUI.SUBADMIN_URL);
        assertThat(response.getUrl().toString(), is(Constants.WebUI.LOGIN_SERVLET));
    }

    /**
     * Test accessing the general area without logging in.
     */
    @Test
    public void testAccessSystemAreaWithoutAuthorisation()
        throws IOException {
    	HtmlPage response = wc.getPage(Constants.WebUI.SYSTEM_URL);
        assertThat(response.getUrl().toString(), is(Constants.WebUI.LOGIN_SERVLET));
    }

    /**
     * Test accessing the includes area without logging in.
     */
    @Test
    public void testAccessIncludesAreaWithoutAuthorisation()
        throws IOException {
        try {
            assertThat(wc.getPage(Constants.WebUI.INCLUDES_URL), is(nullValue()));
        } catch( FailingHttpStatusCodeException ex ) {
            assertThat(ex.getStatusCode(), is(HttpServletResponse.SC_FORBIDDEN));
        }
    }

    /**
     * Test logging in and logging out.
     */
    @Test
    public void testLoginLogoutLoop()
        throws IOException {
        HtmlPage response = TestUtils.loginAsAdmin(wc);
        TestUtils.logout(response);
    }

    /**
     * Test three failed login attempts locks the user out of the system
     */
    @Test
    public void testThreeStrikesAndOut()
        throws IOException {
        String username = "lat1_u"+System.currentTimeMillis();
        String userId = UserTestUtils.createUser(username,"2");

        // Attempt to log in as the user with a bad password twice - should still be enabled.
        loginWithBadCredentials(username);
        loginWithBadCredentials(username);

        // Check that user is still enabled.
        checkEnabled(userId, true);

        // Try for a third time and check the user is disabled.
        loginWithBadCredentials(username);

        // Check that user is still enabled.
        checkEnabled(userId, false);

    }

    /**
     * Test accessing the protected areas without logging in.
     */
    @Test
    public void testTwoStrikesInThreeStrikesOut()
        throws IOException {
        String username = "lat2_u"+System.currentTimeMillis();
        String userId = UserTestUtils.createUser(username,"2");

        // Attempt to log in as the user with a bad password twice - should still be enabled.
        loginWithBadCredentials(username);
        loginWithBadCredentials(username);

        // Check that user is still enabled.
        checkEnabled(userId, true);

        HtmlPage response = TestUtils.login(wc, username, UserTestUtils.DEFAULT_PASSWORD);
        TestUtils.logout(response);

        // Attempt to log in as the user with a bad password twice - should still be enabled.
        loginWithBadCredentials(username);
        loginWithBadCredentials(username);

        // Check that user is still enabled.
        checkEnabled(userId, true);

        // Try for a third time and check the user is disabled.
        loginWithBadCredentials(username);

        // Check that user is still enabled.
        checkEnabled(userId, false);

    }

    /**
     * Perform a login with the incorrect user details.
     *
     * @param username The username to log in with.
     */

    private void loginWithBadCredentials(  String username )
        throws IOException {
        HtmlPage page = wc.getPage(Constants.WebUI.LOGIN_PAGE);
        HtmlForm loginForm = page.getFormByName("logindetails");
        TestUtils.setFormParameter(loginForm, "username", username );
        TestUtils.setFormParameter(loginForm, "password", "xxx" );
        HtmlPage loginFormResponse = TestUtils.submit(loginForm);
        TestUtils.checkForError(loginFormResponse,"There was a problem authorising your details");
    }

    /**
     * Method to check if a user is enabled.
     *
     * @param userId The ID of the user being tested.
     * @param shouldBeEnabled True if the user should be enabled. False if not.
     */

    private void checkEnabled(String userId, boolean shouldBeEnabled)
        throws IOException {
        HtmlPage page = TestUtils.loginAsAdmin(wc).getAnchorByHref(Constants.WebUI.USERS_VIEW_LINK).click();
        page = page.getAnchorByHref(Constants.WebUI.USERS_EDIT_LINK+"?userId="+userId).click();

        HtmlForm form = page.getFormByName("userdetails");
        assertThat(form, is(notNullValue()));
        String enabledFlag  = form.getSelectByName("user_enabled").getDefaultValue();
        if(shouldBeEnabled) {
            assertThat(enabledFlag, is("Y"));
        } else {
            assertThat(enabledFlag, is(not("Y")));
        }

        TestUtils.logout(page);
    }
}
