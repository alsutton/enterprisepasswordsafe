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

import java.io.IOException;

import com.enterprisepasswordsafe.engine.database.ConfigurationOption;
import com.enterprisepasswordsafe.htmlunit.*;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;

import org.junit.Test;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.Assert.assertThat;

public class HierarchyTests extends EPSTestBase {

    /**
     * Get to the hierarchy editing page.
     */

    protected HtmlPage getToHierarchyEditScreen(String username)
    	throws IOException {
        HtmlPage page = TestUtils.login(wc, username, UserTestUtils.DEFAULT_PASSWORD);
        page = page.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
    	return page.getAnchorByHref(Constants.WebUI.EDIT_HIERARCHY_LINK).click();
    }

	/**
     * Test adding a subnode.
     */
    @Test
    public void testAddSubnodeAsSubadministrator()
        throws IOException {
        HtmlPage response = TestUtils.loginAsAdmin(wc);
        response = response.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        response = response.getAnchorByHref(Constants.WebUI.CONFIGURE_LINK).click();
    	HtmlForm configurationForm = response.getFormByName("configurationform");
    	configurationForm.
                getSelectByName(ConfigurationOption.EDIT_USER_MINIMUM_USER_LEVEL.getPropertyName()).
                setSelectedAttribute("S", true);
    	response = TestUtils.submit(configurationForm);
        TestUtils.logout(response);

    	String userName = "addsubnode_subadmin_" + System.currentTimeMillis();
	    UserTestUtils.createUser(userName,"1");

	    String nodeName = "addsubnode_subadmin_" + System.currentTimeMillis();
		response = TestUtils.login(wc, userName, UserTestUtils.DEFAULT_PASSWORD);
        response = HierarchyNodeUtils.createSubnode(nodeName, response);
        TestUtils.logout(response);

    }

    /**
     * Test adding a subnode with the same name as an existing subnode.
     */
    @Test
    public void testAddDuplicateSubnodeAsSubadministrator()
        throws IOException {
    	String userName = "adddupsubnode_subadmin_" + Long.toHexString(System.currentTimeMillis());
	    UserTestUtils.createUser(userName,"1");

	    String nodeName = "adddupsubnode_subadmin_" + Long.toHexString(System.currentTimeMillis());

        HtmlPage currentPage = getToHierarchyEditScreen(userName);
        currentPage = HierarchyNodeUtils.createSubnode(nodeName, currentPage);

        currentPage.getAnchorByText("Add Folder").click();

        HtmlForm newNameForm = currentPage.getFormByName("addfolder");
        newNameForm.getInputByName("name").setValueAttribute(nodeName);
        currentPage = TestUtils.submit(newNameForm);

        TestUtils.checkForError(currentPage, "The node could not be added due to an error.\n(A node with that name already exists).");

        TestUtils.logout(currentPage);
    }


    /**
     * Test navigating to the group folder permissions page.
     */
    @Test
    public void testGroupFolderNavigation()
        throws IOException {
    	String userName = Long.toString(System.currentTimeMillis());
	    UserTestUtils.createUser(userName,"1");
    	String nodeName = "gpermnav_subadmin_" + Long.toString(System.currentTimeMillis());

		HtmlPage response = TestUtils.login(wc, userName, UserTestUtils.DEFAULT_PASSWORD);
        response = HierarchyNodeUtils.createSubnode(nodeName, response);
        response = response.getAnchorByText(nodeName).click();
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");
        response = response.getAnchorByHref(Constants.WebUI.NODE_GROUP_PERMISSIONS_LINK).click();
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");

        response = response.getAnchorByText("Top Level").click();
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");

        TestUtils.logout(response);
    }

    /**
     * Test setting a group permission on a subnode
     */
    @Test
    public void testGroupPermissionSetting()
        throws IOException {

    	String userName = Long.toHexString(System.currentTimeMillis());
	    UserTestUtils.createUser(userName,"1");

    	String username = "gpermset_subadmin_group_" + Long.toHexString(System.currentTimeMillis());
        String groupId = GroupTestUtils.createGroup(username);

        String nodeName = "gpermset_subadmin_node_" + Long.toHexString(System.currentTimeMillis());

		HtmlPage response = TestUtils.login(wc, userName, UserTestUtils.DEFAULT_PASSWORD);
        response = HierarchyNodeUtils.createSubnode(nodeName, response);

        response = response.getAnchorByText(nodeName).click();
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");

        response = response.getAnchorByHref(Constants.WebUI.NODE_GROUP_PERMISSIONS_LINK).click();
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");

        HtmlForm form = response.getFormByName("permset");
        String originalValue = form.getInputByName(groupId+"_orig").getValueAttribute();
        TestUtils.setFormRadioButton(form, groupId+"_perms", "2");
        response = TestUtils.submit(form);
        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");
        TestUtils.checkStatusMessage(response, "Permissions updated.");

        form = response.getFormByName("permset");
        String thisValue = form.getInputByName(groupId+"_orig").getValueAttribute();
        assertThat(thisValue, is("2"));

        TestUtils.setFormRadioButton(form, groupId+"_perms", "1");
        response = TestUtils.submit(form);
        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");
        TestUtils.checkStatusMessage(response, "Permissions updated.");

        form = response.getFormByName("permset");
        thisValue = form.getInputByName(groupId+"_orig").getValueAttribute();
        assertThat(thisValue, is("1"));

        TestUtils.setFormRadioButton(form, groupId+"_perms", "0");
        response = TestUtils.submit(form);
        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");
        TestUtils.checkStatusMessage(response, "Permissions updated.");

        form = response.getFormByName("permset");
        thisValue = form.getInputByName(groupId+"_orig").getValueAttribute();
        assertThat(thisValue, is("0"));

        form.getInputByName(groupId+"_perms").setValueAttribute(originalValue);
        response = TestUtils.submit(form);
        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");
        TestUtils.checkStatusMessage(response, "Permissions updated.");

        form = response.getFormByName("permset");
        thisValue = form.getInputByName(groupId+"_orig").getValueAttribute();
        assertThat(thisValue, is(originalValue));

        TestUtils.logout(response);
    }


    /**
     * Test navigating to the user permissions page on a subfolder.
     */
    @Test
    public void testUserFolderNavigation()
        throws IOException {
    	String userName = Long.toHexString(System.currentTimeMillis());
	    UserTestUtils.createUser(userName,"1");

	    String nodeName = "upnsa_subadmin_" + Long.toHexString(System.currentTimeMillis());

		HtmlPage response = TestUtils.login(wc, userName, UserTestUtils.DEFAULT_PASSWORD);
        response = HierarchyNodeUtils.createSubnode(nodeName, response);

        response = response.getAnchorByText(nodeName).click();
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");

        response = response.getAnchorByHref(Constants.WebUI.NODE_USER_PERMISSIONS_LINK).click();
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");

        response = response.getAnchorByText("Top Level").click();
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");

        TestUtils.logout(response);
    }

    /**
     * Test changing the user permissions on a folder.
     */
    @Test
    public void testUserPermissionSetting()
        throws IOException {
    	String userName =  Long.toHexString(System.currentTimeMillis());
	    UserTestUtils.createUser(userName,"1");

    	String username = "upermset_user_subadmin_" + Long.toHexString(System.currentTimeMillis());
        String userId = UserTestUtils.createUser(username,"2");

        String nodeName = "upermset_node_subadmin_" + Long.toHexString(System.currentTimeMillis());

		HtmlPage response = TestUtils.login(wc, userName, UserTestUtils.DEFAULT_PASSWORD);
        response = HierarchyNodeUtils.createSubnode(nodeName, response);

        response = response.getAnchorByText(nodeName).click();
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");

        response = response.getAnchorByHref(Constants.WebUI.NODE_USER_PERMISSIONS_LINK).click();
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");

        HtmlForm form = response.getFormByName("permset");
        String originalValue = form.getInputByName(userId+"_orig").getValueAttribute();
        TestUtils.setFormRadioButton(form, userId+"_perms", "2");
        response = TestUtils.submit(form);
        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");
        TestUtils.checkStatusMessage(response, "Permissions updated.");

        form = response.getFormByName("permset");
        String thisValue = form.getInputByName(userId+"_orig").getValueAttribute();
        assertThat(thisValue, is("2"));

        TestUtils.setFormRadioButton(form, userId+"_perms", "1");
        response = TestUtils.submit(form);
        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");
        TestUtils.checkStatusMessage(response, "Permissions updated.");

        form = response.getFormByName("permset");
        thisValue = form.getInputByName(userId+"_orig").getValueAttribute();
        assertThat(thisValue, is("1"));

        TestUtils.setFormRadioButton(form, userId+"_perms", "0");
        response = TestUtils.submit(form);
        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");
        TestUtils.checkStatusMessage(response, "Permissions updated.");

        form = response.getFormByName("permset");
        thisValue = form.getInputByName(userId+"_orig").getValueAttribute();
        assertThat(thisValue, is("0"));

        form.getInputByName(userId+"_perms").setValueAttribute(originalValue);
        response = TestUtils.submit(form);
        TestUtils.checkForNoErrors(response);
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");
        TestUtils.checkStatusMessage(response, "Permissions updated.");

        form = response.getFormByName("permset");
        thisValue = form.getInputByName(userId+"_orig").getValueAttribute();
        assertThat(thisValue, is(originalValue));

        TestUtils.logout(response);
    }

    /**
     * Test navigating to the password defaults page for a folder.
     */
    @Test
    public void testNavigationToPasswordDefaults()
        throws IOException {
    	String userName =  Long.toHexString(System.currentTimeMillis());
	    UserTestUtils.createUser(userName,"1");

    	String nodeName = "pdefaultsnav_subadmin_" + Long.toHexString(System.currentTimeMillis());

	    HtmlPage response = TestUtils.login(wc, userName, UserTestUtils.DEFAULT_PASSWORD);
        response = HierarchyNodeUtils.createSubnode(nodeName, response);

        response = response.getAnchorByName("eh_dpa").click();
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");
        assertThat(response.getFormByName("defaultsset"), is(notNullValue()));

        TestUtils.logout(response);
    }

}
