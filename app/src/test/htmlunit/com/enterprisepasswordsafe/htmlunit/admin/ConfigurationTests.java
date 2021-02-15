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
import java.util.List;

import com.enterprisepasswordsafe.engine.database.ConfigurationOption;
import com.enterprisepasswordsafe.htmlunit.Constants;
import com.gargoylesoftware.htmlunit.html.*;
import com.enterprisepasswordsafe.htmlunit.AuthSourceTestUtils;
import com.enterprisepasswordsafe.htmlunit.EPSTestBase;
import com.enterprisepasswordsafe.htmlunit.TestUtils;
import org.junit.Test;

import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;

public class ConfigurationTests extends EPSTestBase {

	/**
	 * The values for the SMTP Server
	 */

	private static final String[] SMTP_TO_VALUES = {
	        "opensource@carbonsecurity.co.uk",
            "noreply@carbonsecurity.co.uk" };


	/**
	 * The values to set for the SMTP host.
	 */

	private final static String[] SMTP_HOST_VALUES = {"testhost.carbonsecurity.co.uk", "localhost"};

	/**
	 * The values to set for the SMTP from address.
	 */

	private final static String[] SMTP_FROM_VALUES = {"eps@localhost", "eps2@localhost"};

	/**
	 * The values to set for a time based field
	 */

	private final static String[] TIME_VALUES = {"0", "5", "60"};

    /**
     * The values for the server base URL
     */

    private static final String[] SERVER_BASE_URL_VALUES = {"http://localhost:123", "http://somewhere.else.com/"};

	/**
	 * The values to set for a counter
	 */

	private final static String[] COUNT_VALUES = {"0", "5", "500"};

	/**
	 * The values for a Y/N option setting
	 */

	private final static String[] YN_SELECTION_VALUES = {"Y", "N"};

	/**
	 * Values used in whether or not the system should be hidden.
	 */

	private final static String[] HIDE_SYSTEMS_VALUES = {"h","s"};

	/**
	 * Values used in the way in which passwords are displayed.
	 */

	private final static String[] PASSWORD_DISPLAY_TYPE_VALUES = {"t","i"};

	/**
	 * The values for a Y/N option setting in lowercase
	 */

	private final static String[] LOWERCASE_YN_SELECTION_VALUES = {"y", "n"};

	/**
	 * The values for a true/false selection option.
	 */

	private final static String[] LOWERCASE_TRUE_FALSE_SELECTION_VALUES = {"true", "false"};

	/**
	 * The values for a true/false selection option.
	 */

	private final static String[] HISTORY_RETENTION_SELECTION_VALUES = {"C", "F", "L"};

	/**
	 * The values for a true/false selection option.
	 */

	private final static String[] AUDITING_SELECTION_VALUES = {"C", "F", "L", "N"};

	/**
	 * The values for the report separator
	 */

	private final static String[] REPORT_SEPARATIR_VALUES = {";", "."};

	/**
	 * The maximum expiry distances.
	 */

	private final static String[] MAX_EXPIRY_VALUES = {"0", "30", "60", "90"};

	/**
	 * The user levels allowed for subadmin and admin level users.
	 */

	private final static String[] USER_LEVEL_VALUES = {"S", "A"};

    /**
     * Test changing the SMTP Host
     */
    @Test
    public void testChangingSMTPHost()
        throws IOException {
    	testParameterSetting("smtphost", SMTP_HOST_VALUES);
    }

    /**
     * Test changing the event emails from address
     */
    @Test
    public void testChangingSMTPFrom()
    	throws IOException {
    	testParameterSetting("smtpfrom", SMTP_FROM_VALUES);
    }

    /**
     * Number of attempts a user can have to login
     */
    @Test
    public void testChangingMaxLoginAttempts()
    	throws IOException {
    	testParameterSetting("user.login_attempts", COUNT_VALUES);
    }

    /**
     * Test changing how users from an unknown login zone are treated.
     */
    @Test
    public void testChangingUnknownIPZoneHandling()
    	throws IOException {
        testSelectSetting("user.login_access", YN_SELECTION_VALUES);
    }

    /**
     * Test changing the session timeout.
     */
    @Test
    public void testChangingSessionTimeout()
    	throws IOException {
    	testParameterSetting( "session.timeout", TIME_VALUES );
    }

    /**
     * Test changing the restricted access request timeout
     */
    @Test
    public void testChangingRARLifetime()
    	throws IOException {
    	testParameterSetting( "rarLifetime", TIME_VALUES );
    }

    @Test
    public void testChangingRAEmailBaseURL()
            throws IOException {
        testParameterSetting( "server_base_url", SERVER_BASE_URL_VALUES );
    }

    /**
     * Test changing whether or not a reason is required for viewing passwords
     */
    @Test
    public void testChangingReasonRequiredForView()
    	throws IOException {
        testSelectSetting("password.reasonrequired", LOWERCASE_YN_SELECTION_VALUES);
    }

    /**
     * Test changing whether or not the system list should be hidden.
     */
    @Test
    public void testChangingHideSystems()
    	throws IOException {
        testSelectSetting("password.hidesystems", LOWERCASE_YN_SELECTION_VALUES);
    }

    /**
     * Test changing the default password display mode (visible or hidden).
     */
    @Test
    public void testChangingPasswordDisplayMode()
    	throws IOException {
        testSelectSetting("password.defaultdisplay", HIDE_SYSTEMS_VALUES);
    }

    /**
     * Test changing the default password display type (text or image).
     */
    @Test
    public void testChangingPasswordDisplayType()
    	throws IOException {
        testSelectSetting("password.displaytype", PASSWORD_DISPLAY_TYPE_VALUES);
    }

    /**
     * Test changing the time a password is on screen.
     */
    @Test
    public void testChangingPasswordDisplayTime()
    	throws IOException {
    	testParameterSetting( "password.onscreen", TIME_VALUES );
    }

    /**
     * Test changing whether or not a user can use the browser back button
     */
    @Test
    public void testChangingPasswordDisplayOnBrowserBack()
    	throws IOException {
        testSelectSetting("password.back_to_password_allowed", LOWERCASE_TRUE_FALSE_SELECTION_VALUES);
    }

    /**
     * Test changing whether or not a subadmin can view the password history
     */
    @Test
    public void testChangingSubadminPasswordHistoryAccess()
    	throws IOException {
        testSelectSetting(ConfigurationOption.SUBADMINS_HAVE_HISTORY_ACCESS, YN_SELECTION_VALUES);
    }

    /**
     * Test changing whether or not the password is hidden during editing
     */
    @Test
    public void testChangingHiddenPasswordOnEdit()
    	throws IOException {
        testSelectSetting("password.entry_hidden", LOWERCASE_TRUE_FALSE_SELECTION_VALUES);
    }

    /**
     * Test rejecting the use of historical expiry dates.
     */
    @Test
    public void testChangingHistoricalExpiryDate()
    	throws IOException {
        testSelectSetting("expiry.allow_historical", YN_SELECTION_VALUES);
    }

    /**
     * Test the setting of the history retention
     */
    @Test
    public void testChangingHistoryRetention()
    	throws IOException {
        testSelectSetting("password.history", HISTORY_RETENTION_SELECTION_VALUES);
    }

    /**
     * Test the setting of the auditing option
     */
    @Test
    public void testChangingAuditing()
    	throws IOException {
        testSelectSetting("password.audit", AUDITING_SELECTION_VALUES);
    }

    /**
     * Test the setting of the auditing option
     */
    @Test
    public void testChangingHierarchyAuditDefault()
    	throws IOException {
    	String[] rules = {"A", "D"};
        testSelectSetting("hierarchy.default_rule", rules);
    }

    /**
     * Test the setting of the auditing option
     */
    @Test
    public void testChangingEmptyFolderHiding()
    	throws IOException {
        testSelectSetting("hierarchy.hide_empty", YN_SELECTION_VALUES);
    }

    /**
     * Test the setting of the default auth source.
     */
    @Test
    public void testDefaultAuthSource()
    	throws IOException {
    	String[]sourceIds = new String[2];
    	for(int i = 0 ; i < 2 ; i++) {
	    	String sourceName = "conf_testdas_"+i+"_"+System.currentTimeMillis();
    		sourceIds[i] = AuthSourceTestUtils.createAuthSource(sourceName);
    	}

        testSelectSetting(ConfigurationOption.DEFAULT_AUTHENTICATION_SOURCE_ID, sourceIds);
    }

    /**
     * Test changing the report seperator
     */
    @Test
    public void testChangingReportSeparator()
    	throws IOException {
    	testParameterSetting( "report.separator", REPORT_SEPARATIR_VALUES);
    }

    /**
     * Test changing the password max expiry distance
     */
    @Test
    public void testChangingPasswordMaxExpiryDistance()
    	throws IOException {
    	testParameterSetting( "expiry.max_distance", MAX_EXPIRY_VALUES);
    }

    /**
     * Test changing the password subadmin editing the hierarchy
     */
    @Test
    public void testChangingHierarchySubadminEdit()
    	throws IOException {
    	testSelectSetting(ConfigurationOption.EDIT_USER_MINIMUM_USER_LEVEL, USER_LEVEL_VALUES);
    }

    /**
     * Test altering a property.
     */
    private void testParameterSetting(String parameterName, String[] values)
        throws IOException {
        HtmlPage htmlPage = TestUtils.loginAsAdmin(wc);
        htmlPage = htmlPage.getAnchorByHref(Constants.WebUI.CONFIGURE_LINK).click();
        TestUtils.checkPageTitle(htmlPage, "Configuration Options");
        htmlPage = setParameterValues( htmlPage, parameterName, values );
        TestUtils.logout(htmlPage);
    }

    private void testSelectSetting(ConfigurationOption option, String[] values)
        throws IOException {
        testSelectSetting(option.getPropertyName(), values);
    }

    private void testSelectSetting(String parameterName, String[] values)
            throws IOException {
        HtmlPage htmlPage = TestUtils.loginAsAdmin(wc);
        htmlPage = htmlPage.getAnchorByHref(Constants.WebUI.CONFIGURE_LINK).click();
        TestUtils.checkPageTitle(htmlPage, "Configuration Options");
        htmlPage = setSelectValues(htmlPage, parameterName, values);
        TestUtils.logout(htmlPage);
    }

    /**
     * Method to update the configuration property with the values specified,
     * cycling through each before resetting the value to the original one.
     *
     * @param response The page
     * @param parameterName The name of the parameter to change.
     * @param parameterValues The values to set.
     */

    private HtmlPage setParameterValues( HtmlPage response, String parameterName, String[] parameterValues )
    	throws IOException
    {
    	HtmlPage currentResponse = response;
    	HtmlForm configurationForm = currentResponse.getFormByName("configurationform");

    	String initialValue = configurationForm.getInputByName(parameterName).getValueAttribute();
    	if(initialValue == null) {
    		initialValue = "";
    	}

        for(String thisParameter : parameterValues) {
    		configurationForm.getInputByName(parameterName).setValueAttribute(thisParameter);
    		currentResponse = TestUtils.submit(configurationForm);
            TestUtils.checkStatusMessage(currentResponse, "The settings have been updated.");

        	configurationForm = currentResponse.getFormByName("configurationform");

        	String newValue = configurationForm.getInputByName(parameterName).getValueAttribute();
            assertThat(newValue, is(thisParameter));
    	}

    	configurationForm.getInputByName(parameterName).setValueAttribute(initialValue);
    	return TestUtils.submit(configurationForm);
    }

    /**
     * Method to update the configuration property with the values specified,
     * cycling through each before resetting the value to the original one.
     *
     * @param response The page
     * @param parameterName The name of the parameter to change.
     * @param parameterValues The values to set.
     */

    private HtmlPage setSelectValues( HtmlPage response, String parameterName, String[] parameterValues )
        throws IOException {
        HtmlPage currentResponse = response;
        HtmlForm configurationForm = currentResponse.getFormByName("configurationform");

        String initialValue = configurationForm.getSelectByName(parameterName).getDefaultValue();
        if(initialValue == null) {
            initialValue = "";
        }

        for(String thisParameter : parameterValues) {
            configurationForm.getSelectByName(parameterName).setSelectedAttribute(thisParameter, true);
            currentResponse = TestUtils.submit(configurationForm);
            TestUtils.checkStatusMessage(currentResponse, "The settings have been updated.");

            configurationForm = currentResponse.getFormByName("configurationform");

            List<HtmlOption> selectedOptions = configurationForm.getSelectByName(parameterName).getSelectedOptions();
            assertThat(selectedOptions.size(), is(1));
            String newValue = selectedOptions.get(0).getValueAttribute();
            assertThat(newValue, is(thisParameter));
        }

        configurationForm.getSelectByName(parameterName).setSelectedAttribute(initialValue, true);
        return TestUtils.submit(configurationForm);
    }

    /**
     * Test changing the email alerts for authentication events.
     */
    @Test
    public void testChangingSMTPAuthenticationEnabled()
    	throws IOException {
        testEmailEventsSelectSetting("smtp.enabled.authentication", YN_SELECTION_VALUES);
    }

    /**
     * Test changing the email alerts for configuration events.
     */
    @Test
    public void testChangingSMTPConfigurationEnabled()
    	throws IOException {
        testEmailEventsSelectSetting("smtp.enabled.configuration", YN_SELECTION_VALUES);
    }

    /**
     * Test changing the email alerts for report events.
     */
    @Test
    public void testChangingSMTPReportsEnabled()
    	throws IOException {
        testEmailEventsSelectSetting("smtp.enabled.reports", YN_SELECTION_VALUES);
    }

    /**
     * Test changing the email alerts for user manipulation events.
     */
    @Test
    public void testChangingSMTPUserManipulationEnabled()
    	throws IOException {
        testEmailEventsSelectSetting("smtp.enabled.user_manipulation", YN_SELECTION_VALUES);
    }

    /**
     * Test changing the email alerts for group manipulation events.
     */
    @Test
    public void testChangingSMTPGroupManipulationEnabled()
    	throws IOException {
        testEmailEventsSelectSetting("smtp.enabled.group_manipulation", YN_SELECTION_VALUES);
    }

    /**
     * Test changing the email alerts for object manipulation events.
     */
    @Test
    public void testChangingSMTPObjectManipulationEnabled()
    	throws IOException {
        testEmailEventsSelectSetting("smtp.enabled.object_manipulation", YN_SELECTION_VALUES);
    }

    /**
     * Test changing the email alerts for hierarchy manipulation events.
     */
    @Test
    public void testChangingSMTPHierarchyManipulationEnabled()
    	throws IOException {
        testEmailEventsSelectSetting("smtp.enabled.user_manipulation", YN_SELECTION_VALUES);
    }

    /**
     * Test changing the event emails from address
     */
    @Test
    public void testChangingSMTPTo()
    	throws IOException {
    	testEmailEventsParameterSetting("smtpto", SMTP_TO_VALUES);
    }

    /**
     * Test changing the SMTP Host
     */
    @Test
    public void testChangingIncludeUser()
    	throws IOException {
        testEmailEventsSelectSetting("audit.email_user", YN_SELECTION_VALUES);
    }


    /**
     * Test altering a property.
     */
    private void testEmailEventsParameterSetting(String parameterName, String[] values)
        throws IOException {
        HtmlPage response = TestUtils.loginAsAdmin(wc);
        response = response.getAnchorByHref(Constants.WebUI.CONFIGURE_EMAIL_LINK).click();
        TestUtils.checkPageTitle(response, "Event Email Settings");
        response = setEmailParameterValues(response, parameterName, values);
        TestUtils.logout(response);
    }

    /**
     * Test altering a property.
     */
    private void testEmailEventsSelectSetting(String parameterName, String[] values)
            throws IOException {
        HtmlPage response = TestUtils.loginAsAdmin(wc);
        response = response.getAnchorByHref(Constants.WebUI.CONFIGURE_EMAIL_LINK).click();
        TestUtils.checkPageTitle(response, "Event Email Settings");
        response = setEmailSelectValues(response, parameterName, values);
        TestUtils.logout(response);
    }

    /**
     * Method to update the configuration property with the values specified,
     * cycling through each before resetting the value to the original one.
     *
     * @param response The current page.
     * @param parameterName The name of the parameter to change.
     * @param parameterValues The values to set.
     */

    private HtmlPage setEmailParameterValues( HtmlPage response, String parameterName,
    		String[] parameterValues )
    	throws IOException
    {
    	HtmlPage currentResponse = response;
    	HtmlForm configurationForm = currentResponse.getFormByName("configurationform");

    	String initialValue = configurationForm.getInputByName(parameterName).getValueAttribute();
    	if(initialValue == null) {
    		initialValue = "";
    	}

    	for( String thisParameter : parameterValues ) {
    		configurationForm.getInputByName(parameterName).setValueAttribute(thisParameter);
    		currentResponse = TestUtils.submit(configurationForm);
            TestUtils.checkStatusMessage(currentResponse, "The settings have been updated.");

        	configurationForm = currentResponse.getFormByName("configurationform");
        	String newValue = configurationForm.getInputByName(parameterName).getValueAttribute();
            assertThat(newValue, is(thisParameter));
    	}

    	configurationForm.getInputByName(parameterName).setValueAttribute(initialValue);
    	return TestUtils.submit(configurationForm);
    }

    /**
     * Method to update the configuration property with the values specified,
     * cycling through each before resetting the value to the original one.
     *
     * @param response The current page.
     * @param parameterName The name of the parameter to change.
     * @param parameterValues The values to set.
     */

    private HtmlPage setEmailSelectValues( HtmlPage response, String parameterName,
                                              String[] parameterValues )
            throws IOException
    {
        HtmlPage currentResponse = response;
        HtmlForm configurationForm = currentResponse.getFormByName("configurationform");

        HtmlSelect select = configurationForm.getSelectByName(parameterName);
        assertThat(select.getOptionSize(), is(2));
        String initialValue = select.getDefaultValue();
        assertThat(initialValue, is(not(nullValue())));

        for( String thisValue : parameterValues ) {
            select = configurationForm.getSelectByName(parameterName);
            select.setSelectedAttribute(thisValue, true);
            currentResponse = TestUtils.submit(configurationForm);
            TestUtils.checkStatusMessage(currentResponse, "The settings have been updated.");

            configurationForm = currentResponse.getFormByName("configurationform");
            select = configurationForm.getSelectByName(parameterName);
            assertThat(select.getDefaultValue(), is(thisValue));
        }

        select = configurationForm.getSelectByName(parameterName);
        select.setSelectedAttribute(initialValue, true);
        return TestUtils.submit(configurationForm);
    }

}
