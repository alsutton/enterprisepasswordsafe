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
import java.util.ArrayList;
import java.util.List;

import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.*;

import static org.hamcrest.CoreMatchers.not;
import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;

public final class TestUtils {

	private TestUtils() {
		// Private constructor to enforce singleton
	}

    /**
     * Log a user into the EPS
     *
     * @param client The web conversation taking place.
     * @param username The username to log in with.
     * @param password The password to log in as.
     *
     * @return The response from the login form.
     *
     * @throws IOException
     */
    public static HtmlPage login(final WebClient client,
    		final String username, final String password)
        throws IOException {
        HtmlPage page = client.getPage(Constants.WebUI.LOGIN_PAGE);
        assertThat(page.getUrl().toString(), is(Constants.WebUI.LOGIN_SERVLET));
        HtmlForm loginForm = page.getFormByName("logindetails");
        loginForm.getInputByName("username").setValueAttribute(username);
        loginForm.getInputByName("password").setValueAttribute( password );

        page = TestUtils.submit(loginForm);

        return page;
    }


    /**
     * Log a user in as admin.
     *
     * @param client The web client in use.
     *
     * @return The response from the login form
     *
     * @throws IOException
     */
    public static HtmlPage loginAsAdmin(final WebClient client)
        throws IOException {
    	return login(client, "admin", "admin");
    }

    /**
     * Log the user out.
     *
     * @param page The page the user is on.
     */

    public static HtmlPage logout(final HtmlPage page)
    	throws IOException {
        HtmlAnchor anchor = page.getAnchorByHref(Constants.WebUI.LOGOUT_LINK);
        assertThat(anchor, is(notNullValue()));
        HtmlPage logoutPage = anchor.click();
        assertThat( "Got "+logoutPage.getUrl().toString()+" after logout.",
                    logoutPage.getUrl().toString().endsWith(Constants.WebUI.LOGIN_PAGE),
                    is(true));
        return logoutPage;
    }


    /**
     * Check the page title is correct.
     *
     * @param page The page to check the title on.
     * @param expectedTitle The title that should be on the page
     */

    public static void checkPageTitle(final HtmlPage page, final String expectedTitle) {
        String title = page.getTitleText();
        assertThat(title, is(notNullValue()));
        assertThat(title.isEmpty(), is(false));
        assertThat(title, is("EPS : " + expectedTitle));
    }

    /**
     * Ensure that no errors have been reported.
     *
     * @param page The page to check for errors on.
     */

    public static void checkForNoErrors(final HtmlPage page) {
    	DomElement element = page.getElementById("errormessage");
        String elementContent;
        if(element != null) {
            elementContent = element.getTextContent();
        } else {
            elementContent = "";
        }
        assertThat("Found error :"+elementContent, element, is(nullValue()));
    }

    /**
     * Ensure that a specific error has been reported.
     *
     * @param page The page to check for the error.
     * @param expectedText The expected error text.
     */

    public static void checkForError(final HtmlPage page, final String expectedText) {
        DomElement element = page.getElementById("errormessage");
        assertThat(element, is(notNullValue()));
        assertThat(element.getTextContent(), is(expectedText));
    }

    /**
     * Ensure a specific status message has been reported.
     *
     * @param page The page to check for the status message.
     * @param expectedText The expected status message.
     */

    public static void checkStatusMessage(final HtmlPage page, final String expectedText) {
        DomElement element = page.getElementById("statusmessage");
        assertThat(element, is(notNullValue()));

    	String text = element.getTextContent();
        assertThat(text, is(notNullValue()));
        assertThat(text, is(expectedText));
    }

    /**
     * Get the names of all the parameters in a form.
     *
     * @param form The form to get the parameters for.
     *
     * @return An List of String objects holding the parameter names
     */

    public static List<String> getFormParameterNames(final HtmlForm form) {
        List<String> parameterNames = new ArrayList<String>();
        for(HtmlElement element : form.getHtmlElementsByTagName("input")) {
            parameterNames.add(element.getAttribute("name"));
        }
        return parameterNames;
    }

    /**
     * Submit a form.
     *
     * @param form The form to submit
     *
     * @return The page the user was taken to after the submission
     */

    public static HtmlPage submit(final HtmlForm form)
        throws IOException {
        List<HtmlElement> elements = form.getElementsByAttribute("button", "type", "submit");
        assertThat(elements.isEmpty(), is(false));

        for(HtmlElement element : elements) {
            String classes = element.getAttribute("class");
            if(classes == null) {
                continue;
            }
            if(classes.contains("btn-primary")) {
                return element.click();
            }
        }

        return elements.get(0).click();
    }

    /**
     * Submit a form using a specific submit button.
     *
     * @param form The form to submit
     * @param name The name of the button.
     * @param id The id of the button to use.
     *
     * @return The page the user was taken to after the submission
     */

    public static HtmlPage submit(final HtmlForm form, String name, final String id)
            throws IOException {
        HtmlButton submitButton = null;
        for(HtmlButton button : form.getButtonsByName(name)) {
            if(button.getId().equals(id)) {
                submitButton = button;
            }
        }

        assertThat(submitButton, is(not(nullValue())));
        assert(submitButton != null);
        return submitButton.click();
    }

    /**
     * Get the currently set value of a form parameter
     *
     * @param form The form to set a value in.
     * @param name The name of the input value to set.
     *
     * @return The value to set it to.
     */

    public static String getFormParameterValue(final HtmlForm form, final String name) {
        return form.getInputByName(name).getValueAttribute();
    }

    /**
     * Set a value in a form
     *
     * @param form The form to set a value in.
     * @param name The name of the input value to set.
     * @param value The value to set it to.
     */

    public static void setFormParameter(final HtmlForm form, final String name, final String value) {
        form.getInputByName(name).setValueAttribute(value);
    }

    /**
     * Set a value in a form
     *
     * @param form The form to set a value in.
     * @param name The name of the input value to set.
     * @param value The value to set it to.
     */

    public static void setFormParameter(final HtmlForm form, final String name, final boolean value) {
        form.getInputByName(name).setChecked(value);
    }

    /**
     * Select a radio button from a set of radio buttons.
     */

    public static void setFormRadioButton(final HtmlForm form, final String name, final String value) {
        List<HtmlRadioButtonInput> radioButtons = form.getRadioButtonsByName(name);
        for(HtmlRadioButtonInput thisButton : radioButtons) {
            if(thisButton.getValueAttribute().equals(value)) {
                thisButton.setChecked(true);
                return;
            }
        }
    }

    /**
     * Select a radio button from a set of radio buttons.
     */

    public static void setFormSelect(final HtmlForm form, final String name, final String value) {
        HtmlSelect select = form.getSelectByName(name);
        select.setSelectedAttribute(value, true);
    }

    /**
     * Gets the text held between in a <span></span>.
     *
     * @param page The page to search
     * @param spanId The ID of the span to look for
     */

    public static String getSpanText(final HtmlPage page, final String spanId) {
        final List<DomElement> spans = page.getElementsByTagName("span");
        for (DomElement element : spans) {
            if (element.getAttribute("id").equals(spanId)) {
                String text = element.getTextContent();
                return (text == null) ? null : text.trim();
            }
        }

        return null;
    }
}
