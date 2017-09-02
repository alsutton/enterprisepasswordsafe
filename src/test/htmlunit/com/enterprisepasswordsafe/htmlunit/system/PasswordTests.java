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
import java.util.ArrayList;
import java.util.List;

import com.enterprisepasswordsafe.htmlunit.*;
import com.gargoylesoftware.htmlunit.html.*;

import org.junit.Test;

import static org.hamcrest.CoreMatchers.*;
import static org.junit.Assert.assertThat;

public class PasswordTests extends EPSTestBase {

    private static final String NON_ENGLISH_NOTES_STRING = "Unit testing ä, ö, ü, ß";

    /**
     * Test enabling and disabling a password
     */
    @Test
    public void testEnableDisablePassword()
        throws IOException {
        String passwordRunId = PasswordTestUtils.createPassword(wc);
        HtmlPage response = TestUtils.loginAsAdmin(wc);

        response = response.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();

        HtmlAnchor link = response.getAnchorByText("pu"+passwordRunId);
        assertThat(link, is(notNullValue()));
        response = link.click();

        link = response.getAnchorByText("Edit details");
        assertThat(link, is(notNullValue()));
        response = link.click();

        String values[] = { "Y", "N" };
    	response = switchRadioValues(response, "enabled", values);

    	if( response != null ) {
    		TestUtils.logout(response);
    	}
    }

    /**
     * Test a password is non expiring by default.
     */

    @Test
    public void testDefaultNonExpiringPassword()
        throws IOException {
        String passwordRunId = PasswordTestUtils.createPassword(wc);
        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        currentPage = currentPage.getAnchorByText("pu"+passwordRunId).click();
        currentPage = currentPage.getAnchorByText("Edit details").click();

        HtmlForm passwordForm = currentPage.getFormByName("editform");
        assertThat(passwordForm.getInputByName("expiryDate").getValueAttribute().isEmpty(), is(true));

        TestUtils.logout(currentPage);
    }

    /**
     * Test a password is non expiring by default.
     */

    @Test
    public void testBackButtonBlocked()
            throws IOException {
        String passwordRunId = PasswordTestUtils.createPassword(wc);
        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();

        HtmlAnchor anchor = currentPage.getAnchorByText("pu"+passwordRunId);
        currentPage = anchor.click();
        String viewUrl = currentPage.getUrl().toString();
        currentPage = currentPage.getAnchorByText("Edit details").click();

        currentPage = currentPage.getWebClient().getPage(viewUrl);

        TestUtils.checkForError(currentPage, "You can not view passwords using your browsers back button.");

        TestUtils.logout(currentPage);
    }


    /**
     * Test viewing a password
     */
    @Test
    public void testViewPassword()
        throws IOException {
        String passwordRunId = PasswordTestUtils.createPassword(wc);

        HtmlPage response = TestUtils.loginAsAdmin(wc);
        response = response.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();

        HtmlAnchor link = response.getAnchorByText("pu"+passwordRunId);
        assertThat(link, is(notNullValue()));

        response = link.click();
        DomElement element = response.getElementById("username");
        assertThat(element.getTextContent().trim(), is("pu"+passwordRunId));

        element = response.getElementById("system");
        assertThat(element.getTextContent().trim(), is("pl"+passwordRunId));

        TestUtils.logout(response);
    }

    @Test
    public void testEditWithoutChangingPasswordInformation()
            throws IOException {
        String passwordRunId = PasswordTestUtils.createPassword(wc);

        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        currentPage = currentPage.getAnchorByText("pu" + passwordRunId).click();
        currentPage = currentPage.getAnchorByText("Edit details").click();
        currentPage = TestUtils.submit(currentPage.getFormByName("editform"));

        TestUtils.checkForNoErrors(currentPage);
        assertThat(currentPage.getElementById("username").getTextContent().trim(), is("pu"+passwordRunId));
        assertThat(currentPage.getElementById("system").getTextContent().trim(), is("pl"+passwordRunId));

        TestUtils.logout(currentPage);
    }

    /**
     * Test showing and hiding a password.
     */
    @Test
    public void testShowHidePassword()
        throws IOException {
        String passwordRunId = PasswordTestUtils.createPassword(wc);

        HtmlPage response = TestUtils.loginAsAdmin(wc);

        response = response.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        response = response.getAnchorByText("pu"+passwordRunId).click();

        HtmlForm toggleForm = response.getFormByName("passwordshowhideform");
        assertThat(toggleForm, is(notNullValue()));
        response =  TestUtils.submit(toggleForm);
        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "View Password");

        toggleForm = response.getFormByName("passwordshowhideform");
        assertThat(toggleForm, is(notNullValue()));
        response =  TestUtils.submit(toggleForm);
        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "View Password");

        toggleForm = response.getFormByName("passwordshowhideform");
        assertThat(toggleForm, is(notNullValue()));
        TestUtils.logout(response);
    }

    /**
     * Test restricted access requests.
     */
    @Test
    public void testRestrictedAccessRequests()
        throws IOException {
        String userEnding = Long.toHexString(System.currentTimeMillis());
        String[] usernames = new String[2];
        usernames[0] = "RAoutstanding1"+userEnding;
        usernames[1] = "RAoutstanding2"+userEnding;

    	// Create a 2 users
        String[] userIds = new String[2];
        UserTestUtils.createMultipleUsers(userIds, usernames,"2");

    	// Create two passwords which are accessible by the users.
        String[] passwordNames = new String[2];
        String[] passwordIds = new String[2];
        for(int i = 0 ; i < passwordNames.length ; i++) {
            passwordNames[i] = "RAtest_" + mRunId + "_" + i;
            PasswordTestUtils.loginAndCreatePasswordWithName(wc, passwordNames[i]);
            passwordIds[i] = setupPassword(passwordNames[i], userIds);
            passwordNames[i] = "pu"+passwordNames[i];
        }

        // Login as the user and attempt to access two the locked passwords.
        HtmlPage response = TestUtils.login(wc, usernames[0], UserTestUtils.DEFAULT_PASSWORD);
        for(int i = 0 ; i < 2 ; i++) {
            response = response.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        	response = response.getAnchorByText(passwordNames[i]).click();
        	HtmlForm form = response.getFormByName("rareason");
        	form.getTextAreaByName("reason").setText("junittest");
        	response = TestUtils.submit(form);
        	TestUtils.checkForNoErrors(response);
        }
        TestUtils.logout(response);

        // Log in as the other user and check the RA list.
        response = TestUtils.login(wc, usernames[1], UserTestUtils.DEFAULT_PASSWORD);
        response = response.getAnchorByHref(Constants.WebUI.RESTRICTED_ACCESS_REQUEST_LINK).click();
        assertThat(response.getAnchorByName("rar_"+passwordIds[0]), is(notNullValue()));
        assertThat(response.getAnchorByName("rar_"+passwordIds[1]), is(notNullValue()));
        TestUtils.logout(response);
    }

    /**
     * Test clicking on a system name to search for a list of passwords in a given location
     */
    @Test
    public void testPasswordLocationSearch() throws IOException {
        String runId = Long.toString(System.currentTimeMillis());

        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = PasswordTestUtils.createPassword(currentPage, "locsearch_1_"+runId, runId);
        currentPage = PasswordTestUtils.createPassword(currentPage, "locsearch_2_"+runId, runId);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.SEARCH_LOCATION_LINK+"?location="+runId).click();

        assertThat(currentPage.getAnchorByText("locsearch_1_"+runId+"@"+runId), is(notNullValue()));
        assertThat(currentPage.getAnchorByText("locsearch_2_"+runId+"@"+runId), is(notNullValue()));

        TestUtils.logout(currentPage);
    }

    /**
     * Test setting and changing the expiry date of a password.
     */

    @Test
    public void testSettingAndChangingExpiryDate()
        throws IOException {
        String runId = Long.toString(System.currentTimeMillis());

        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.CREATE_PASSWORD_LINK).click();
        HtmlForm form = currentPage.getFormByName("editform");
        form.getInputByName("username").setValueAttribute("tSACE_"+runId);
        form.getInputByName("password_1").setValueAttribute(PasswordTestUtils.DEFAULT_PASSWORD);
        form.getInputByName("password_2").setValueAttribute(PasswordTestUtils.DEFAULT_PASSWORD);
        form.getInputByName("expiryDate").setValueAttribute("25-MAR-2020");
        form.getInputByName("location_text").setValueAttribute("tSACE_l_"+runId);
        form.getTextAreaByName("notes").setText("Unit testing test password");
        currentPage = TestUtils.submit(form);

        TestUtils.checkForNoErrors(currentPage);
        TestUtils.checkStatusMessage(currentPage, "The password was successfully created.");

        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        currentPage = currentPage.getAnchorByText("tSACE_"+runId).click();

        assertThat(currentPage.getElementById("expiry").getTextContent().trim(), is("25-Mar-2020"));

        currentPage = currentPage.getAnchorByText("Edit details").click();

        form = currentPage.getFormByName("editform");
        assertThat(form.getInputByName("expiryDate").getValueAttribute(), is("25-Mar-2020"));
        form.getInputByName("expiryDate").setValueAttribute("25-Mar-2025");
        currentPage = TestUtils.submit(form);

        TestUtils.checkForNoErrors(currentPage);

        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        currentPage = currentPage.getAnchorByText("tSACE_"+runId).click();

        assertThat(currentPage.getElementById("expiry").getTextContent().trim(), is("25-Mar-2025"));
        TestUtils.logout(currentPage);

    }

    /**
     * Method to switch the values on a set of radio buttons.
     *
     * @param page The current page being looked at
     * @param fieldName The name of the rad to change
     * @param values The values to switch to.
     */

    private HtmlPage switchRadioValues(final HtmlPage page, String fieldName, String[] values)
            throws IOException {
        HtmlForm passwordForm = page.getFormByName("editform");
        String initialValue = passwordForm.getCheckedRadioButton(fieldName).getValueAttribute();

        HtmlPage currentResponse = page;
        for(String value : values) {
            passwordForm = currentResponse.getFormByName("editform");
            HtmlUnitUtils.setRadioButton(passwordForm, fieldName, value);
            currentResponse = TestUtils.submit(passwordForm);

            TestUtils.checkForNoErrors(currentResponse);
            TestUtils.checkStatusMessage(currentResponse, "The password was successfully changed.");

            HtmlAnchor link = currentResponse.getAnchorByText("Edit details");
            assertThat(link, is(notNullValue()));
            currentResponse = link.click();

            passwordForm = currentResponse.getFormByName("editform");
            assertThat(passwordForm.getCheckedRadioButton(fieldName).getValueAttribute(), is(value));
        }

        passwordForm = currentResponse.getFormByName("editform");
        HtmlUnitUtils.setRadioButton(passwordForm, fieldName, initialValue);
        currentResponse = TestUtils.submit(passwordForm);

        HtmlAnchor link = currentResponse.getAnchorByText("Edit details");
        assertThat(link, is(notNullValue()));
        return link.click();
    }

    /**
     * Method to allow access to a password for a set of users. It also sets the first
     * user in the array to have the RA approver right for the password.
     *
     * @param passwordRunId The runId so the password can be found.
     * @param userIds The IDs of the users to allow access.
     */

    private String setupPassword(String passwordRunId, String[] userIds)
    	throws IOException {
    	HtmlPage response = TestUtils.loginAsAdmin(wc);
        response = response.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
    	HtmlAnchor passwordLink = response.getAnchorByText("pu"+passwordRunId);
        String linkAddress = passwordLink.getHrefAttribute();
        int idParamStart = linkAddress.indexOf("id=");
        assertThat(idParamStart, is(not(-1)));

        idParamStart += 3;
        int idParamEnd = linkAddress.indexOf("&", idParamStart);
        if(idParamEnd == -1) {
            idParamEnd = linkAddress.length();
        }
        String passwordInternalId = linkAddress.substring(idParamStart, idParamEnd);

    	response = passwordLink.click();

    	response = response.getAnchorByText("Alter access").click();
    	HtmlForm form = response.getFormByName("editaccess");

    	String accessParameterNames[] = new String[2];
    	String accessParamStartStrings[] = new String[2];
    	String raParameterNames[] = new String[2];
    	for(int j = 0 ; j < 2 ; j++) {
    		accessParamStartStrings[j] = "u_"+userIds[j]+"_a";
    		raParameterNames[j] = "ur_"+userIds[j];
    	}

        List<String> paramNamesList = new ArrayList<>();
        for(HtmlElement thisElement : form.getHtmlElementsByTagName("input")) {
            paramNamesList.add(thisElement.getAttribute("name"));
        }
        String[] paramNames = paramNamesList.toArray(new String[paramNamesList.size()]);
        for (String paramName : paramNames) {
            for (int k = 0; k < 2; k++) {
                if (paramName.startsWith(accessParamStartStrings[k])) {
                    accessParameterNames[k] = paramName;
                }
            }
        }
    	for(int j = 0 ; j < 2 ; j++) {
            assertThat(accessParameterNames[j], is(notNullValue()));
            HtmlUnitUtils.setRadioButton(form, accessParameterNames[j], "R");
    	}

		form.getInputByName(raParameterNames[1]).setChecked(true);
        response = TestUtils.submit(form);
        TestUtils.checkForNoErrors(response);


    	response = response.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
    	response = response.getAnchorByText("pu"+passwordRunId).click();
    	response = response.getAnchorByText("Edit details").click();
    	form = response.getFormByName("editform");
        HtmlUnitUtils.setRadioButton(form, "ra_enabled", "Y");
    	form.getInputByName("ra_approvers").setValueAttribute("1");
    	response = TestUtils.submit(form);
        TestUtils.checkForNoErrors(response);

        TestUtils.logout(response);

        return passwordInternalId;
    }


    @Test
    public void testNonEnglishCharactersInNotesField()
            throws IOException {
        String passwordRunId = PasswordTestUtils.createPassword(wc);
        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);

        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();

        HtmlAnchor link = currentPage.getAnchorByText("pu"+passwordRunId);
        assertThat(link, is(notNullValue()));
        currentPage = link.click();

        currentPage = currentPage.getAnchorByText("Edit details").click();

        HtmlForm passwordForm = currentPage.getFormByName("editform");
        passwordForm.getTextAreaByName("notes").setText(NON_ENGLISH_NOTES_STRING);
        currentPage = TestUtils.submit(passwordForm);

        TestUtils.checkForNoErrors(currentPage);

        currentPage = currentPage.getAnchorByText("Edit details").click();

        passwordForm = currentPage.getFormByName("editform");
        assertThat(passwordForm.getTextAreaByName("notes").getText(), is(NON_ENGLISH_NOTES_STRING));

        TestUtils.logout(currentPage);
    }

}
