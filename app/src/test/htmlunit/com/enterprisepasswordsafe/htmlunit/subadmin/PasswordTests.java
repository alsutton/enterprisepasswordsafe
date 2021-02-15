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

package com.enterprisepasswordsafe.htmlunit.subadmin;

import java.io.*;

import com.gargoylesoftware.htmlunit.html.*;
import com.enterprisepasswordsafe.htmlunit.Constants;
import com.enterprisepasswordsafe.htmlunit.EPSTestBase;
import com.enterprisepasswordsafe.htmlunit.GroupTestUtils;
import com.enterprisepasswordsafe.htmlunit.HierarchyNodeUtils;
import com.enterprisepasswordsafe.htmlunit.PasswordTestUtils;
import com.enterprisepasswordsafe.htmlunit.TestUtils;
import com.enterprisepasswordsafe.htmlunit.UserTestUtils;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class PasswordTests extends EPSTestBase {

    /**
     * Test creating a password with one custom field.
     */
    @Test
    public void testCreatePasswordWithOneCustomField()
        throws IOException {

        String runId = "pwdwithcfields_" +System.currentTimeMillis();

        HtmlPage response = TestUtils.loginAsAdmin(wc);
        response = response.getAnchorByHref(Constants.WebUI.CREATE_PASSWORD_LINK).click();
        assertThat(response.getUrl().toString(), is(Constants.WebUI.CREATE_PASSWORD_SERVLET));

        HtmlForm form = response.getFormByName("editform");
        TestUtils.setFormParameter(form,"username", "pu"+runId);
        TestUtils.setFormParameter(form,"password_1", "abc123");
        TestUtils.setFormParameter(form,"password_2", "abc123");
        TestUtils.setFormParameter(form, "location_text", "pl" + runId);
        form.getTextAreaByName("notes").setText("Unit testing test password");
        response = TestUtils.submit(form,"newCF","newCF");

        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Create a new password");

        form = response.getFormByName("editform");
        assertThat(TestUtils.getFormParameterValue(form,"cfn_0"), is("New Field 1"));
        assertThat(TestUtils.getFormParameterValue(form,"cfv_0"), is(""));

        response = TestUtils.submit(form);
        TestUtils.checkStatusMessage(response, "The password was successfully created.");

        String text = response.getElementById("username").getTextContent();
        assertThat(text.trim(), is("pu"+runId));

        text = response.getElementById("system").getTextContent();
        assertThat(text.trim(), is("pl"+runId));

        TestUtils.logout(response);
    }

    /**
     * Test creating a password with two custom fields.
     */
    @Test
    public void testCreatePasswordWithTwoCustomField()
        throws IOException {

        String runId = "pwdwith2cfields_" + System.currentTimeMillis();

        HtmlPage response = TestUtils.loginAsAdmin(wc);
        response = response.getAnchorByHref(Constants.WebUI.CREATE_PASSWORD_LINK).click();
        assertThat(response.getUrl().toString(), is(Constants.WebUI.CREATE_PASSWORD_SERVLET));

        HtmlForm form = response.getFormByName("editform");
        TestUtils.setFormParameter(form,"username", "pu"+runId);
        TestUtils.setFormParameter(form,"password_1", "abc123");
        TestUtils.setFormParameter(form,"password_2", "abc123");
        TestUtils.setFormParameter(form, "location_text", "pl" + runId);
        form.getTextAreaByName("notes").setText("Unit testing test password");
        response = TestUtils.submit(form, "newCF","newCF");

        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Create a new password");

        form = response.getFormByName("editform");
        TestUtils.setFormParameter(form,"cfn_0", "CF1");
        TestUtils.setFormParameter(form,"cfv_0", "XXX");
        response = TestUtils.submit(form, "newCF","newCF");

        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Create a new password");

        form = response.getFormByName("editform");
        assertThat(TestUtils.getFormParameterValue(form,"cfn_0"),is("CF1"));
        assertThat(TestUtils.getFormParameterValue(form,"cfv_0"),is("XXX"));
        assertThat(TestUtils.getFormParameterValue(form,"cfn_1"),is("New Field 2"));
        assertThat(TestUtils.getFormParameterValue(form,"cfv_1"),is(""));

        response = TestUtils.submit(form);
        TestUtils.checkStatusMessage(response, "The password was successfully created.");
        assertThat(response.getElementById("username").getTextContent().trim(), is("pu"+runId));
        assertThat(response.getElementById("system").getTextContent().trim(), is("pl"+runId));

        TestUtils.logout(response);
    }

    /**
     * Test creating a password with two custom fields and then deleting the fields.
     */
    @Test
    public void testCreatePasswordWithTwoCustomFieldAndDeleteFields()
        throws IOException {

        String runId = "pwdwith2cfieldsdel_" +System.currentTimeMillis();

        HtmlPage response = TestUtils.loginAsAdmin(wc);
        response = response.getAnchorByHref(Constants.WebUI.CREATE_PASSWORD_LINK).click();
        assertThat(response.getUrl().toString(), is(Constants.WebUI.CREATE_PASSWORD_SERVLET));

        HtmlForm form = response.getFormByName("editform");
        TestUtils.setFormParameter(form,"username", "pu"+runId);
        TestUtils.setFormParameter(form,"password_1", "abc123");
        TestUtils.setFormParameter(form,"password_2", "abc123");
        TestUtils.setFormParameter(form, "location_text", "pl" + runId);
        form.getTextAreaByName("notes").setText("Unit testing test password");
        response = TestUtils.submit(form, "newCF","newCF");

        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Create a new password");

        form = response.getFormByName("editform");
        TestUtils.setFormParameter(form,"cfn_0", "CF1");
        TestUtils.setFormParameter(form,"cfv_0", "XXX");
        response = TestUtils.submit(form, "newCF","newCF");

        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Create a new password");

        form = response.getFormByName("editform");
        assertThat(TestUtils.getFormParameterValue(form,"cfn_0"), is("CF1"));
        assertThat(TestUtils.getFormParameterValue(form,"cfv_0"), is("XXX"));
        assertThat(TestUtils.getFormParameterValue(form,"cfn_1"), is("New Field 2"));
        assertThat(TestUtils.getFormParameterValue(form,"cfv_1"), is(""));
        response = TestUtils.submit(form);

        TestUtils.checkStatusMessage(response,"The password was successfully created.");
        assertThat(response.getElementById("username").getTextContent().trim(), is("pu"+runId));
        assertThat(response.getElementById("system").getTextContent().trim(), is("pl"+runId));

        response = response.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        response = response.getAnchorByText("pu"+runId).click();
        response = response.getAnchorByText("Edit details").click();

        form = response.getFormByName("editform");
        assertThat(TestUtils.getFormParameterValue(form,"cfn_0"), is("CF1"));
        assertThat(TestUtils.getFormParameterValue(form, "cfv_0"), is("XXX"));
        assertThat(TestUtils.getFormParameterValue(form, "cfn_1"), is("New Field 2"));
        assertThat(TestUtils.getFormParameterValue(form, "cfv_1"), is(""));

        TestUtils.setFormParameter(form,"cfd_0", true);
        TestUtils.setFormParameter(form,"cfd_1", true);
        response = TestUtils.submit(form);

        response = response.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        response = response.getAnchorByText("pu"+runId).click();
        response = response.getAnchorByText("Edit details").click();

        form = response.getFormByName("editform");
        for(String thisParameterName : TestUtils.getFormParameterNames(form)) {
            assertThat(thisParameterName, is(not("cfn_0")));
            assertThat(thisParameterName, is(not("cfn_1")));
        }

        TestUtils.logout(response);
    }

    /**
     * Test creating a password with one custom field.
     */
    @Test
    public void testCreateDuplicatePassword()
        throws IOException {

        String runId = "pwddupecheck_" + System.currentTimeMillis();
        String passwordUsername = "pu"+runId;

        HtmlPage response = TestUtils.loginAsAdmin(wc);
        response = response.getAnchorByHref(Constants.WebUI.CREATE_PASSWORD_LINK).click();

        HtmlForm form = response.getFormByName("editform");
        TestUtils.setFormParameter(form,"username", passwordUsername);
        TestUtils.setFormParameter(form,"password_1", "abc123");
        TestUtils.setFormParameter(form,"password_2", "abc123");
        TestUtils.setFormParameter(form,"location_text", "pl"+runId);
        form.getTextAreaByName("notes").setText("Unit testing test password");
        response = TestUtils.submit(form);

        response = response.getAnchorByHref(Constants.WebUI.CREATE_PASSWORD_LINK).click();
        form = response.getFormByName("editform");
        TestUtils.setFormParameter(form,"username", passwordUsername);
        TestUtils.setFormParameter(form,"password_1", "abc123");
        TestUtils.setFormParameter(form,"password_2", "abc123");
        TestUtils.setFormParameter(form,"location_text", "pl"+runId);
        form.getTextAreaByName("notes").setText("Unit testing test password");
        response = TestUtils.submit(form);

        response = response.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        int linkCount = 0;
        for(HtmlAnchor anchor : response.getAnchors()) {
            if(anchor.getTextContent().trim().equals(passwordUsername)) {
                linkCount++;
            }
        }
        assertThat(linkCount, is(2));

        TestUtils.logout(response);
    }


    /**
     * Test logging in and logging out.
     */
    @Test
    public void testAdminUserGivingAccess()
        throws IOException {
        String userEnding = Long.toHexString(System.currentTimeMillis());
        String[] usernames = new String[2];
        String[] userIds = new String[2];
        usernames[0] = "adminAR1"+userEnding;
        usernames[1] = "adminAR2"+userEnding;

    	// Create a 2 admin users
        UserTestUtils.createMultipleUsers(userIds, usernames, "0");

    	// Create a password
        String password = "pu"+PasswordTestUtils.createPassword(wc);

    	// Edit the password as the admin and allow the other user read rights
        HtmlPage response = TestUtils.login(wc, usernames[0], UserTestUtils.DEFAULT_PASSWORD);
        response = response.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        response = response.getAnchorByText(password).click();

        response = response.getAnchorByText("Alter access").click();

        HtmlForm form = response.getFormByName("editaccess");
		String paramStartString = "u_"+userIds[1]+"_a";
		String parameterName = null;
        for(String thisParameterName : TestUtils.getFormParameterNames(form)) {
			if( thisParameterName.startsWith(paramStartString) ) {
				parameterName = thisParameterName;
				break;
			}
		}
        assertThat(parameterName, is(notNullValue()));

        TestUtils.setFormParameter(form,parameterName, "R");
        response = TestUtils.submit(form);

        TestUtils.checkForNoErrors(response);
        TestUtils.logout(response);

    	// Try to access the password as the non-admin user.
        response = TestUtils.login(wc, usernames[1], UserTestUtils.DEFAULT_PASSWORD);
        response = response.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        response = response.getAnchorByText(password).click();
        TestUtils.checkForNoErrors(response);
        TestUtils.logout(response);
    }
}
