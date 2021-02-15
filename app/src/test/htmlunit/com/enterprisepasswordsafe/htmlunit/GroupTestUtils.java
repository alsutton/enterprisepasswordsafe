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
import com.gargoylesoftware.htmlunit.html.*;

import java.io.IOException;
import java.util.Set;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.Assert.assertThat;

/**
 * Base class for tests dealing with the created user.
 */
public class GroupTestUtils  {

    /**
     * Private constructor to enforce singleton.
     */
    public GroupTestUtils() {
    	// Private constructor.
    }

    /**
     * Create a new group.
     *
     * @param groupName The name of the group to create.
     * @return The ID of the group
     */

    public static String createGroup( String groupName )
    	throws IOException {
        WebClient wc = new WebClient();

        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.GROUPS_VIEW_LINK).click();
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.GROUPS_CREATE_LINK).click();

        TestUtils.checkPageTitle(currentPage, "Create Group");

        HtmlForm form = currentPage.getFormByName("newgroupdetails");
        form.getInputByName("groupname").setValueAttribute(groupName);
        currentPage = TestUtils.submit(form);

        TestUtils.checkPageTitle(currentPage, "Edit Group");

        TestUtils.checkStatusMessage(currentPage, "The group was successfully created.");

        testGroupForm(currentPage, groupName, 1, true);

        HtmlForm groupDetails = currentPage.getFormByName("groupdetails");
        String groupId = groupDetails.getInputByName("group_id").getValueAttribute();

        TestUtils.logout(currentPage);
        return groupId;
    }

    /**
     * Create multiple new groups.
     *
     * @param ids The array to store the group ids in.
     * @param names The array holding the names of the groups to create.
     */

    public static void createGroups( Set<String> ids, String[] names )
    	throws IOException {
        WebClient wc = new WebClient();
        HtmlPage response = TestUtils.loginAsAdmin(wc);
        for(String thisName : names) {
	        response = response.getAnchorByHref(Constants.WebUI.GROUPS_CREATE_LINK).click();
	        HtmlForm form = response.getFormByName("newgroupdetails");
	        form.getInputByName("groupname").setValueAttribute(thisName);
	        response = TestUtils.submit(form);

	        HtmlForm groupDetails = response.getFormByName("groupdetails");
	        ids.add(groupDetails.getInputByName("group_id").getValueAttribute());
        }
        TestUtils.logout(response);
        wc.closeAllWindows();
    }

    /**
     * Check that the group form details match our expectations.
     *
     * @param page The page containing the form to text.
     * @param groupName The name of the group to test.
     * @param expectedCount The expected number of users in the group.
     * @param expectedEnabledStatus The expected status of the group.
     */
    public static void testGroupForm(HtmlPage page, String groupName,
    		int expectedCount, boolean expectedEnabledStatus)
        throws IOException {
    	HtmlForm form = page.getFormByName("groupdetails");
        String text = form.getInputByName("name").getValueAttribute();
        assertThat(text, is(groupName));

        HtmlSelect enabledSelect = form.getSelectByName("enabled");
        assertThat(enabledSelect.getOptionSize(), is(2));
        String enabledString = enabledSelect.getDefaultValue();
        assertThat(enabledString, is(notNullValue()));
        if(expectedEnabledStatus) {
            assertThat(enabledString, is("Y"));
        } else {
            assertThat(enabledString, is("N"));
        }

        text = page.getElementById("groupcount").getTextContent();
        assertThat(text.isEmpty(), is(false));
        int count = Integer.parseInt(text);
        assertThat(count, is(expectedCount));
    }

    /**
     * Test if a group exists
     *
     * @param groupId The ID of the group to check for.
     *
     * @return true if the group exists, false if not.
     */

    public static boolean groupExists( String groupId )
        throws IOException {
    	WebClient wc = new WebClient();
        HtmlPage response = TestUtils.loginAsAdmin(wc);
	    response = response.getAnchorByHref(Constants.WebUI.GROUPS_VIEW_LINK).click();
	    boolean exists = (response.getAnchorByHref(Constants.WebUI.GROUPS_EDIT_LINK + "?group_id="+groupId) != null);
	    TestUtils.logout(response);
        wc.closeAllWindows();

	    return exists;
    }
}
