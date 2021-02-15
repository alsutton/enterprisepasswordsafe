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

import java.io.*;

import com.enterprisepasswordsafe.htmlunit.*;
import com.gargoylesoftware.htmlunit.ElementNotFoundException;
import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.html.*;
import org.junit.Test;

import javax.servlet.http.HttpServletResponse;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;

public final class UserTests extends EPSTestBase {

    /**
     * Test creating and deleting an individual user.
     */
    @Test
    public void testDeleteSingleUser()
        throws IOException {
        String userName = "sudel_" + System.currentTimeMillis();
        String userId = UserTestUtils.createUser(userName,"2");

        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.USERS_VIEW_LINK).click();
        currentPage = currentPage.getAnchorByName("delete_"+userName).click();

        TestUtils.checkStatusMessage(currentPage,"The user "+userName+" has been deleted");

        TestUtils.logout(currentPage);

        assertThat(UserTestUtils.userExists(userId), is(false));
    }

    /**
     * Test accessing the admin area as a logged in normal user
     */
    @Test
    public void testNonAdminAccessingAdminArea()
        throws IOException {
        String userName = "new_user_user_"+ System.currentTimeMillis();
        UserTestUtils.createUser(userName,"2");

        TestUtils.login(wc, userName, UserTestUtils.DEFAULT_PASSWORD);
        try {
        	assertThat(wc.getPage(Constants.WebUI.ADMIN_URL), is(nullValue()));
        } catch(FailingHttpStatusCodeException e) {
            assertThat(e.getStatusCode(), is(HttpServletResponse.SC_FORBIDDEN));
        }
    }

    /**
     * Test accessing the subadmin area as a logged in normal user
     */
    @Test
    public void testNonAdminAccessingSubadminArea()
        throws IOException {
        String userName = "new_user_user_"+ System.currentTimeMillis();
        UserTestUtils.createUser(userName,"2");

        TestUtils.login(wc, userName, UserTestUtils.DEFAULT_PASSWORD);
        try {
        	assertThat(wc.getPage(Constants.WebUI.SUBADMIN_URL), is(nullValue()));
        } catch(FailingHttpStatusCodeException e) {
            assertThat(e.getStatusCode(), is(HttpServletResponse.SC_FORBIDDEN));
        }
    }


    /**
     * Test accessing the protected areas without logging in.
     */
    @Test
    public void testEditUser()
        throws IOException {
        String userName = "new_user_user_"+ System.currentTimeMillis();
        UserTestUtils.createUser(userName,"2");

        HtmlPage response = TestUtils.loginAsAdmin(wc);
        response = response.getAnchorByHref(Constants.WebUI.USERS_VIEW_LINK).click();

        TestUtils.checkPageTitle(response, "Users");

        response = findLinkForUser(response, userName).click();

        HtmlForm form = response.getFormByName("userdetails");
        UserTestUtils.verifyUserForm(form, userName);

        TestUtils.logout(response);
    }

    /**
     * Test accessing the protected areas without logging in.
     */
    @Test
    public void testGroupAddAndRemove()
        throws IOException {
        String userName = "new_user_user_"+ System.currentTimeMillis();
        UserTestUtils.createUser(userName,"2");

        String groupName = "usergroupaddremove_group_"+System.currentTimeMillis();
        String groupId = GroupTestUtils.createGroup(groupName);

        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.USERS_VIEW_LINK).click();

        TestUtils.checkPageTitle(currentPage, "Users");

        currentPage = findLinkForUser(currentPage, userName).click();

        HtmlForm userForm = currentPage.getFormByName("userdetails");
        userForm.getInputByName("group_"+groupId).setChecked(true);
        currentPage = TestUtils.submit(userForm);

        TestUtils.checkForNoErrors(currentPage);

        userForm = currentPage.getFormByName("userdetails");
        assertThat(userForm.getInputByName("group_" + groupId).isChecked(), is(true));
        userForm.getInputByName("group_"+groupId).setChecked(false);
        currentPage = TestUtils.submit(userForm);

        TestUtils.checkForNoErrors(currentPage);

        userForm = currentPage.getFormByName("userdetails");
        assertThat(userForm.getInputByName("group_"+groupId).isChecked(), is(false));

        TestUtils.logout(currentPage);
    }

    /**
     * Test forcing the user to reset their password
     */
    @Test
    public void testForcePasswordReset()
        throws IOException {
        String userName = "new_user_user_"+ System.currentTimeMillis();
        UserTestUtils.createUser(userName,"2");

        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        assertThat(currentPage.getAnchorByHref(Constants.WebUI.EXPLORER_LINK), is(notNullValue()));

        currentPage = currentPage.getAnchorByHref(Constants.WebUI.USERS_VIEW_LINK).click();

        TestUtils.checkPageTitle(currentPage, "Users");

        currentPage = findLinkForUser(currentPage, userName).click();

        HtmlForm form = currentPage.getFormByName("userdetails");
        TestUtils.setFormSelect(form, "force_change_password", "Y");
        currentPage = TestUtils.submit(form);

        TestUtils.checkForNoErrors(currentPage);
        TestUtils.checkStatusMessage(currentPage, "The profile has been updated.");

        TestUtils.logout(currentPage);

        currentPage = TestUtils.login(wc, userName, UserTestUtils.DEFAULT_PASSWORD);
        TestUtils.checkPageTitle(currentPage, "Change Login Password");

        form = currentPage.getFormByName("passwordchange");
        assertThat(form, is(notNullValue()));

        try {
            assertThat(currentPage.getAnchorByHref(Constants.WebUI.EXPLORER_LINK), is(nullValue()));
        } catch(ElementNotFoundException e) {
            // Do nothing, this is what we want to happen.
        }

        form.getInputByName("currentpassword").setValueAttribute(UserTestUtils.DEFAULT_PASSWORD);
        form.getInputByName("password1").setValueAttribute("AAAA");
        form.getInputByName("password2").setValueAttribute("AAAA");
        currentPage = TestUtils.submit(form);

        TestUtils.checkForNoErrors(currentPage);

        TestUtils.logout(currentPage);
    }

    /**
     * Test importing a user.
     */
    @Test
    public void testImportingUser()
        throws IOException {
        String runId = Long.toString(System.currentTimeMillis());
        String username = "uimport_"+runId;

        final String importText = username+", Test User "+username+", al@alsutton.com, N, abc123";

        HtmlPage response = TestUtils.loginAsAdmin(wc);
        response = response.getAnchorByHref(Constants.WebUI.USERS_VIEW_LINK).click();
        response = response.getAnchorByHref(Constants.WebUI.USERS_IMPORT_LINK).click();
        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Import Users");

        HtmlForm form = response.getFormByName("importform");
        HtmlFileInput fileInput = form.getInputByName("file");
        fileInput.setValueAttribute("import.csv");
        fileInput.setContentType("text/csv");
        fileInput.setData(importText.getBytes("UTF-8"));
        response = TestUtils.submit(form);

        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Results of import");

        response = response.getAnchorByHref(Constants.WebUI.USERS_VIEW_LINK).click();
        response = findLinkForUser(response, username).click();
        HtmlForm userDetails = response.getFormByName("userdetails");

        assertThat(userDetails.getInputByName("username").getValueAttribute(), is(username) );
        assertThat(userDetails.getSelectByName("user_type").getDefaultValue(), is("2") );
        assertThat(userDetails.getInputByName("fn").getValueAttribute(), is("Test User "+username) );
        assertThat(userDetails.getInputByName("em").getValueAttribute(), is("al@alsutton.com") );
        assertThat(userDetails.getSelectByName("auth_source").getDefaultValue(), is("0") );
        assertThat(userDetails.getSelectByName("user_enabled").getDefaultValue(), is("Y") );

        TestUtils.logout(response);

        response = TestUtils.login(wc, username, "abc123");
        TestUtils.logout(response);
    }

    /**
     * Test importing an EPS admin.
     */
    @Test
    public void testImportingEPSAdminUser()
        throws IOException {
        String runId = Long.toString(System.currentTimeMillis());
        String username = "uimportutype0_"+runId;

        final String importText = username+", Test User, al@alsutton.com, E, abc123";

        HtmlPage response = TestUtils.loginAsAdmin(wc);
        response = response.getAnchorByHref(Constants.WebUI.USERS_VIEW_LINK).click();
        response = response.getAnchorByHref(Constants.WebUI.USERS_IMPORT_LINK).click();
        HtmlForm form = response.getFormByName("importform");
        HtmlFileInput fileInput = form.getInputByName("file");
        fileInput.setContentType("text/csv");
        fileInput.setValueAttribute("import.csv");
        fileInput.setData(importText.getBytes("UTF-8"));
        response = TestUtils.submit(form);

        TestUtils.checkForNoErrors(response);

        response = response.getAnchorByHref(Constants.WebUI.USERS_VIEW_LINK).click();
        response = findLinkForUser(response, username).click();
        HtmlForm userDetails = response.getFormByName("userdetails");
        assertThat(userDetails.getSelectByName("user_type").getDefaultValue(), is("0") );

        TestUtils.logout(response);
    }

    /**
     * Test importing an password admin.
     */
    @Test
    public void testImportingPasswordAdminUser()
        throws IOException {
        String runId = Long.toString(System.currentTimeMillis());
        String username = "uimportutype1_"+runId;

        final String importText = "EPS\n"+username+", Test User, al@alsutton.com, P, abc123";

        HtmlPage response = TestUtils.loginAsAdmin(wc);
        response = response.getAnchorByHref(Constants.WebUI.USERS_VIEW_LINK).click();
        response = response.getAnchorByHref(Constants.WebUI.USERS_IMPORT_LINK).click();
        HtmlForm form = response.getFormByName("importform");
        HtmlFileInput fileInput = form.getInputByName("file");
        fileInput.setContentType("text/csv");
        fileInput.setValueAttribute("import.csv");
        fileInput.setData(importText.getBytes("UTF-8"));
        response = TestUtils.submit(form);

        TestUtils.checkForNoErrors(response);

        response = response.getAnchorByHref(Constants.WebUI.USERS_VIEW_LINK).click();
        response = findLinkForUser(response, username).click();
        HtmlForm userDetails = response.getFormByName("userdetails");
        assertThat(userDetails.getSelectByName("user_type").getDefaultValue(), is("1"));

        TestUtils.logout(response);
    }


    /**
     * Test importing a normal user.
     */
    @Test
    public void testImportingNormalUser()
        throws IOException {
        String runId = Long.toString(System.currentTimeMillis());
        String username = "uimportutype2_"+runId;

        final String importText = "EPS\n"+username+", Test User, al@alsutton.com, N, abc123";

        HtmlPage response = TestUtils.loginAsAdmin(wc);
        response = response.getAnchorByHref(Constants.WebUI.USERS_VIEW_LINK).click();
        response = response.getAnchorByHref(Constants.WebUI.USERS_IMPORT_LINK).click();
        HtmlForm form = response.getFormByName("importform");
        HtmlFileInput fileInput = form.getInputByName("file");
        fileInput.setContentType("text/csv");
        fileInput.setValueAttribute("import.csv");
        fileInput.setData(importText.getBytes("UTF-8"));
        response = TestUtils.submit(form);

        TestUtils.checkForNoErrors(response);

        response = response.getAnchorByHref(Constants.WebUI.USERS_VIEW_LINK).click();
        response = findLinkForUser(response, username).click();
        HtmlForm userDetails = response.getFormByName("userdetails");
        assertThat(userDetails.getSelectByName("user_type").getDefaultValue(), is("2"));

        TestUtils.logout(response);
    }

    /**
     * Test creating a non-viewing user
     */

    @Test
    public void testCreatingNonViewingUser()
        throws IOException {
        HtmlPage page = TestUtils.loginAsAdmin(wc);
        page = page.getAnchorByHref(Constants.WebUI.USERS_VIEW_LINK).click();
        page = page.getAnchorByHref(Constants.WebUI.USERS_EDIT_LINK).click();

        TestUtils.checkPageTitle(page, "User Profile");

        HtmlForm form = page.getFormByName("userdetails");

        String runId = Long.toString(System.currentTimeMillis());
        form.getInputByName("fn").setValueAttribute("HTML Unit tCNVU_"+runId);
        form.getInputByName("username").setValueAttribute("tCNVU_"+runId);
        form.getInputByName("em").setValueAttribute("test@carbonsecurity.co.uk");

        form.getInputByName("password1").setValueAttribute(PasswordTestUtils.DEFAULT_PASSWORD);
        form.getInputByName("password2").setValueAttribute(PasswordTestUtils.DEFAULT_PASSWORD);
        page = TestUtils.submit(form);

        TestUtils.checkStatusMessage(page, "The profile has been created.");

        TestUtils.logout(page);
    }

    /**
     * Test setting an IP Zone and removing it.
     */

    @Test
    public void testUserRestrictionManipulation()
        throws IOException {
        String zoneName = "tURM_zone_"+Long.toString(System.currentTimeMillis());
        String zoneId = NetworkZoneUtils.addIPV4Zone(wc, zoneName);

        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.USERS_VIEW_LINK).click();
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.USERS_EDIT_LINK).click();

        TestUtils.checkPageTitle(currentPage, "User Profile");

        HtmlForm form = currentPage.getFormByName("userdetails");

        String runId = Long.toString(System.currentTimeMillis());
        form.getInputByName("fn").setValueAttribute("HTML Unit tURM_"+runId);
        form.getInputByName("username").setValueAttribute("tURM_"+runId);
        form.getInputByName("em").setValueAttribute("test@carbonsecurity.co.uk");

        form.getInputByName("password1").setValueAttribute(PasswordTestUtils.DEFAULT_PASSWORD);
        form.getInputByName("password2").setValueAttribute(PasswordTestUtils.DEFAULT_PASSWORD);

        TestUtils.setFormSelect(form, "zone_"+zoneId, "N");

        currentPage = TestUtils.submit(form);

        TestUtils.checkStatusMessage(currentPage, "The profile has been created.");
        TestUtils.checkForNoErrors(currentPage);

        currentPage = currentPage.getAnchorByHref(Constants.WebUI.USERS_VIEW_LINK).click();
        currentPage = findLinkForUser(currentPage, "tURM_"+runId).click();

        form = currentPage.getFormByName("userdetails");
        assertThat(form.getSelectByName("zone_"+zoneId).getDefaultValue(), is("N"));
        form.getSelectByName("zone_"+zoneId).setSelectedAttribute("Y", true);
        currentPage = TestUtils.submit(form);

        currentPage = currentPage.getAnchorByHref(Constants.WebUI.USERS_VIEW_LINK).click();
        currentPage = findLinkForUser(currentPage, "tURM_"+runId).click();

        form = currentPage.getFormByName("userdetails");
        assertThat(form.getSelectByName("zone_"+zoneId).getDefaultValue(), is("Y"));
        form.getSelectByName("zone_"+zoneId).setSelectedAttribute("D", true);
        currentPage = TestUtils.submit(form);

        currentPage = currentPage.getAnchorByHref(Constants.WebUI.USERS_VIEW_LINK).click();
        currentPage = findLinkForUser(currentPage, "tURM_"+runId).click();

        form = currentPage.getFormByName("userdetails");
        assertThat(form.getSelectByName("zone_"+zoneId).getDefaultValue(), is("D"));

        TestUtils.logout(currentPage);
    }

    /**
     * Search for the link to a users details given their username
     */

    private HtmlAnchor findLinkForUser(HtmlPage page, final String username) {
        return page.getAnchorByName("edit_"+username);
    }
}
