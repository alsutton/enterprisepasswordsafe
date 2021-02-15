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
import com.gargoylesoftware.htmlunit.ElementNotFoundException;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlInput;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.junit.Test;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.nullValue;
import static org.junit.Assert.assertThat;

public class PasswordRestrictionTests extends EPSTestBase {

    /**
     * Test accessing the protected areas without logging in.
     */
    @Test
    public void testCreateRestriction()
        throws IOException {
        String name = "pradd_"+System.currentTimeMillis();
        PasswordRestrictionUtils.createPasswordRestriction(name);
    }

    /**
     * Test accessing the protected areas without logging in.
     */
    @Test
    public void testDeleteRestriction()
        throws IOException {
        String name = "prdelete_"+System.currentTimeMillis();
        PasswordRestrictionUtils.createPasswordRestriction(name);

        HtmlPage response = TestUtils.loginAsAdmin(wc);

        response = response.getAnchorByHref(Constants.WebUI.PASSWORD_RESTRICTIONS_LINK).click();
        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Password Restrictions");

        response = response.getAnchorByName("delete_"+name).click();
        TestUtils.checkForNoErrors(response);

        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Password Restrictions");

        // Check old link has gone
        try {
            assertThat(response.getAnchorByName("delete_" + name), is(nullValue()));
        } catch(ElementNotFoundException e) {
            // This is what should happen, the element should not exist.
        }

        TestUtils.logout(response);
    }

    /**
     * Test the deleting of a restriction which is in use, this should fail.
     */
    @Test
    public void testDeleteRestrictionInUse()
        throws IOException {
        String name = "prdelete_"+System.currentTimeMillis();
        String restrictionId = PasswordRestrictionUtils.createPasswordRestriction(name);

        String passwordName = PasswordTestUtils.createPassword(wc);

        HtmlPage response = TestUtils.loginAsAdmin(wc);
        response = response.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        response = response.getAnchorByText("pu"+passwordName).click();
        response = response.getAnchorByText("Edit details").click();
        HtmlForm form = response.getFormByName("editform");
        HtmlUnitUtils.setSelectedOptions(form, "restriction_id", restrictionId);
        form.getInputByName("password_1").setValueAttribute("#1aA#1aA");
        form.getInputByName("password_2").setValueAttribute("#1aA#1aA");
        response = TestUtils.submit(form);

        TestUtils.checkForNoErrors(response);
        TestUtils.checkStatusMessage(response, "The password was successfully changed.");
        TestUtils.checkPageTitle(response, "View Password");

        response = response.getAnchorByHref(Constants.WebUI.PASSWORD_RESTRICTIONS_LINK).click();
        response = response.getAnchorByName("delete_"+name).click();

        TestUtils.checkPageTitle(response, "Restriction Removal Blocked");

        response = response.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        response = response.getAnchorByText("pu"+passwordName).click();
        response = response.getAnchorByText("Edit details").click();
        form = response.getFormByName("editform");
        HtmlUnitUtils.setSelectedOptions(form, "restriction_id", "-2");
        response = TestUtils.submit(form);

        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "View Password");

        response = response.getAnchorByHref(Constants.WebUI.PASSWORD_RESTRICTIONS_LINK).click();
        response = response.getAnchorByName("delete_"+name).click();

        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Password Restrictions");

        // Check old link has gone
        try {
            assertThat(response.getAnchorByName("delete_"+name), is(nullValue()));
        } catch(ElementNotFoundException e) {
            // This is what should happen, the element should not exist.
        }

        TestUtils.logout(response);
    }

    /**
     * Test accessing the protected areas without logging in.
     */
    @Test
    public void testChangeRestriction()
        throws IOException {
        String name = "predit_"+System.currentTimeMillis();
	    PasswordRestrictionUtils.createPasswordRestriction(name);

        HtmlPage response = TestUtils.loginAsAdmin(wc);

        response = response.getAnchorByHref(Constants.WebUI.PASSWORD_RESTRICTIONS_LINK).click();
        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Password Restrictions");

        response = response.getAnchorByName("edit_"+name).click();
        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Edit Password Restriction");

        HtmlForm form = response.getFormByName("editform");
        changeValue(form, "name", name, name+"_new");
        changeValue(form, "size_min", "1", "2");
        changeValue(form, "size_max", "8", "16");
        changeValue(form, "upper_min", "1", "3");
        changeValue(form, "lower_min", "1", "4");
        changeValue(form, "numeric_min", "1", "5");
        changeValue(form, "special_min", "1", "6");
        changeValue(form, "chars_special", 	"#!.", "#$!^");
        response = TestUtils.submit(form);

        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Password Restrictions");

        // Check old link has gone
        try {
            assertThat(response.getAnchorByName("edit_"+name), is(nullValue()));
        } catch(ElementNotFoundException e) {
            // This is what should happen, the element should not exist.
        }

        response = response.getAnchorByName("edit_"+name+"_new").click();
        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Edit Password Restriction");

        form = response.getFormByName("editform");
        changeValue(form, "name", 				name+"_new", name);
        changeValue(form, "size_min", "2", "0");
        changeValue(form, "size_max", "16", "8");
        changeValue(form, "upper_min", "3", "0");
        changeValue(form, "lower_min", "4", "0");
        changeValue(form, "numeric_min", "5", "0");
        changeValue(form, "special_min", "6", "0");
        changeValue(form, "chars_special", 	"#$!^", "#!.");
        response = TestUtils.submit(form);

        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Password Restrictions");

        TestUtils.logout(response);
    }

    /**
     * Change the value of a parameter checking it was correct in the first place.
     *
     * @param form The form being changed.
     * @param parameter The parameter to change.
     * @param expectedValue The value which should be the current value of the input.
     * @param newValue The value to set the input to.
     */
    private void changeValue(final HtmlForm form, final String parameter,
    		final String expectedValue, final String newValue) {
        HtmlInput htmlInput = form.getInputByName(parameter);
        String value = htmlInput.getValueAttribute();
        assertThat(value, is(expectedValue));
        htmlInput.setValueAttribute(newValue);
    }
}
