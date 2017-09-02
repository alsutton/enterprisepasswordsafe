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
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.junit.Test;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.Assert.assertThat;

public class SubnodeManipulationTest extends EPSTestBase {

    /**
     * Create a subnode and return it's ID.
     *
     * @param page The hierarchy editing page.
     * @param nodeName The name of the node to create.
     *
     * @return page The page the user is on after the creation.
     */

    protected HtmlPage createSubnode(final HtmlPage page, final String nodeName)
    	throws IOException {
        HtmlPage currentPage = page.getAnchorByText("Add Folder").click();

        HtmlForm addForm = currentPage.getFormByName("addfolder");
        addForm.getInputByName("name").setValueAttribute(nodeName);
        return TestUtils.submit(addForm);
    }

	/**
     * Test accessing the protected areas without logging in.
     */
    @Test
    public void testAddSubnode()
        throws IOException {
        String nodeName = "addsubnode_" +System.currentTimeMillis();
        HtmlPage response = navigateToHierarchyEditorAsAdmin();
        response = createSubnode(response, nodeName);
        TestUtils.checkForNoErrors(response);
        TestUtils.checkStatusMessage(response, "The node has been created.");
        TestUtils.logout(response);
    }

    /**
     * Test accessing the protected areas without logging in.
     */
    @Test
    public void testAddDuplicateSubnode()
        throws IOException {
        String nodeName = "adddupsubnode_" +System.currentTimeMillis();
        HtmlPage response = navigateToHierarchyEditorAsAdmin();
        response = createSubnode(response, nodeName);

        TestUtils.checkStatusMessage(response, "The node has been created.");
        response = createSubnode(response, nodeName);

        TestUtils.checkForError(response, "The node could not be added due to an error.\n(A node with that name already exists).");

        TestUtils.logout(response);
    }


    /**
     * Test accessing the protected areas without logging in.
     */
    @Test
    public void testGroupFolderNavigation()
        throws IOException {
    	String nodeName = "gpermnav_" +System.currentTimeMillis();
        HtmlPage response = navigateToHierarchyEditorAsAdmin();
        response = createSubnode(response, nodeName);

        response = response.getAnchorByText(nodeName).click();
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");

        response = response.getAnchorByHref(Constants.WebUI.NODE_GROUP_PERMISSIONS_LINK).click();
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");

        response = response.getAnchorByText("Top Level").click();
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");

        TestUtils.logout(response);
    }

    /**
     * Test accessing the protected areas without logging in.
     */
    @Test
    public void testGroupPermissionSetting()
        throws IOException {

    	String username = "gpermset_group_" + System.currentTimeMillis();
        String groupId = GroupTestUtils.createGroup(username);

        String nodeName = "gpermset_node_" + System.currentTimeMillis();
        HtmlPage response = navigateToHierarchyEditorAsAdmin();
        response = createSubnode(response, nodeName);

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
     * Test accessing the protected areas without logging in.
     */
    @Test
    public void testUserFolderNavigation()
        throws IOException {
    	String nodeName = "upnsa_" + System.currentTimeMillis();
        HtmlPage response = navigateToHierarchyEditorAsAdmin();
        response = createSubnode(response, nodeName);
        response = response.getAnchorByText(nodeName).click();
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");

        response = response.getAnchorByHref(Constants.WebUI.NODE_USER_PERMISSIONS_LINK).click();
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");

        response = response.getAnchorByText("Top Level").click();
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");

        TestUtils.logout(response);
    }

    /**
     * Test accessing the protected areas without logging in.
     */
    @Test
    public void testUserPermissionSetting()
        throws IOException {

    	String username = "upermset_user_" + Long.toHexString(System.currentTimeMillis());
        String userId = UserTestUtils.createUser(username,"2");

        String nodeName = "upermset_node_" + Long.toHexString(System.currentTimeMillis());
        HtmlPage response = navigateToHierarchyEditorAsAdmin();
        response = createSubnode(response, nodeName);

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
     * Test accessing the default password properties
     */
    @Test
    public void testNavigationToPasswordDefaults()
        throws IOException {
        HtmlPage response = navigateToHierarchyEditorAsAdmin();

        response = response.getAnchorByName("eh_dpa").click();
        TestUtils.checkPageTitle(response, "Edit Password Hierarchy");

        assertThat(response.getFormByName("defaultsset"), is(notNullValue()));

        TestUtils.logout(response);
    }

    /**
     * Navigate to the hierarchy editor
     */

    private HtmlPage navigateToHierarchyEditorAsAdmin()
        throws IOException {
        HtmlPage page = TestUtils.loginAsAdmin(wc);
        page = page.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        return page.getAnchorByHref(Constants.WebUI.EDIT_HIERARCHY_LINK).click();
    }
}
