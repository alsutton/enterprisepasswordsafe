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
import java.nio.charset.Charset;

import com.enterprisepasswordsafe.htmlunit.*;
import com.gargoylesoftware.htmlunit.ElementNotFoundException;
import com.gargoylesoftware.htmlunit.html.*;
import org.junit.Test;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.Assert.assertThat;

public class GroupTests extends EPSTestBase {

    /**
     * Test creating and deleting an individual group.
     */
    @Test
    public void testDeleteSingleGroup()
        throws IOException {
        String groupName = "sgdel_" + System.currentTimeMillis();
        String groupId = GroupTestUtils.createGroup(groupName);

        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.GROUPS_VIEW_LINK).click();
        currentPage = currentPage.getAnchorByName("del_"+groupName).click();

        TestUtils.checkStatusMessage(currentPage,"The group "+groupName+" has been deleted");

        TestUtils.logout(currentPage);

        try {
            assertThat(GroupTestUtils.groupExists(groupId), is(false));
        } catch (ElementNotFoundException enfe) {
            // This is correct.
        }
    }

    /**
     * Test editing the group information.
     */
    @Test
    public void testEditGroup()
        throws Exception {
        String runId = Long.toString(System.currentTimeMillis());
        String groupName = "teg_"+runId;
    	GroupTestUtils.createGroup(groupName);

        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.GROUPS_VIEW_LINK).click();

        TestUtils.checkPageTitle(currentPage, "Groups");

        currentPage = currentPage.getAnchorByName("edit_"+groupName).click();

        GroupTestUtils.testGroupForm(currentPage, "teg_"+runId, 1, true);

        TestUtils.logout(currentPage);
    }

    /**
     * Test Disable/Enable Group
     */
    @Test
    public void testDisableAndEnableGroup()
        throws IOException {
        String groupName = "grpenable_"+System.currentTimeMillis();
    	GroupTestUtils.createGroup(groupName);

        HtmlPage response = TestUtils.loginAsAdmin(wc);
        response = response.getAnchorByHref(Constants.WebUI.GROUPS_VIEW_LINK).click();

        response = response.getAnchorByName("edit_"+groupName).click();

        HtmlForm form = response.getFormByName("groupdetails");
        assertThat(form.getSelectByName("enabled").getDefaultValue(), is("Y"));

        TestUtils.setFormSelect(form, "enabled", "N");
        response = TestUtils.submit(form);
        TestUtils.checkForNoErrors(response);

        form = response.getFormByName("groupdetails");
        assertThat(form.getSelectByName("enabled").getDefaultValue(), is("N"));
        TestUtils.setFormSelect(form, "enabled", "Y");
        response = TestUtils.submit(form);
        TestUtils.checkForNoErrors(response);

        form = response.getFormByName("groupdetails");
        assertThat(form.getSelectByName("enabled").getDefaultValue(), is("Y"));

        TestUtils.logout(response);
    }

    /**
     * Test Renaming Group
     */
    @Test
    public void testRenameGroup()
        throws IOException {
        String groupName = "grprename_"+System.currentTimeMillis();
    	GroupTestUtils.createGroup(groupName);

        HtmlPage response = TestUtils.loginAsAdmin(wc);
        HtmlAnchor link = response.getAnchorByHref(Constants.WebUI.GROUPS_VIEW_LINK);
        response = link.click();

        response = response.getAnchorByName("edit_"+groupName).click();

        HtmlForm form = response.getFormByName("groupdetails");
        assertThat(form.getInputByName("name").getValueAttribute(), is(groupName));
        form.getInputByName("name").setValueAttribute(groupName+"_New");
        response = TestUtils.submit(form);
        TestUtils.checkForNoErrors(response);

        form = response.getFormByName("groupdetails");
        assertThat(form.getInputByName("name").getValueAttribute(), is(groupName+"_New"));
        form.getInputByName("name").setValueAttribute(groupName);
        response = TestUtils.submit(form);
        TestUtils.checkForNoErrors(response);

        form = response.getFormByName("groupdetails");
        assertThat(form.getInputByName("name").getValueAttribute(), is(groupName));

        TestUtils.logout(response);
    }


    /**
     * Test accessing the protected areas without logging in.
     */
    @Test
    public void testImportingGroup()
        throws IOException {
        String runId = Long.toString(System.currentTimeMillis());
        String groupName = "gimport_"+runId;

        String importString = groupName;

        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.GROUPS_VIEW_LINK).click();
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.GROUPS_IMPORT_LINK).click();
        TestUtils.checkForNoErrors(currentPage);
        TestUtils.checkPageTitle(currentPage, "Import Groups");

        HtmlForm form = currentPage.getFormByName("importform");
        HtmlFileInput fileInput = form.getInputByName("file");
        fileInput.setValueAttribute("import.csv");
        fileInput.setContentType("text/csv");
        fileInput.setData(importString.getBytes());
        currentPage = TestUtils.submit(form);

        TestUtils.checkForNoErrors(currentPage);
        TestUtils.checkPageTitle(currentPage, "Results of import");

        currentPage = currentPage.getAnchorByHref(Constants.WebUI.GROUPS_VIEW_LINK).click();

        TestUtils.checkForNoErrors(currentPage);

        assertThat(currentPage.getAnchorByName("edit_"+groupName), is(notNullValue()));

        TestUtils.logout(currentPage);
    }

    /**
     * Test accessing the protected areas without logging in.
     */
    @Test
    public void testImportingGroupWithUsers()
        throws IOException {

        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);

        String runId = Long.toString(System.currentTimeMillis());

        String[] ids = new String[2];
    	String[] names = new String[2];
    	names[0] = "gimport_u1_"+runId;
    	names[1] = "gimport_u2_"+runId;
        currentPage = UserTestUtils.createMultipleUsers(currentPage, ids, names, "2");

        String groupName = "gimportu_"+runId;

        StringWriter sw = new StringWriter();
    	try {
	        PrintWriter importFileWriter = new PrintWriter(sw);
            importFileWriter.println("EPS");
            importFileWriter.print(groupName);
            importFileWriter.print(',');
            importFileWriter.print(names[0]);
            importFileWriter.print(',');
            importFileWriter.print(names[1]);
            importFileWriter.flush();

            currentPage = currentPage.getAnchorByHref(Constants.WebUI.GROUPS_VIEW_LINK).click();
            currentPage = currentPage.getAnchorByHref(Constants.WebUI.GROUPS_IMPORT_LINK).click();
	        TestUtils.checkForNoErrors(currentPage);
	        TestUtils.checkPageTitle(currentPage, "Import Groups");

	        HtmlForm form = currentPage.getFormByName("importform");
	        HtmlFileInput fileInput = form.getInputByName("file");
            fileInput.setValueAttribute("import.csv");
            fileInput.setContentType("text/string");

            String data = sw.getBuffer().toString();
            fileInput.setData(data.getBytes(Charset.forName("UTF-8")));
            currentPage = TestUtils.submit(form);

	        TestUtils.checkForNoErrors(currentPage);
	        TestUtils.checkPageTitle(currentPage, "Results of import");

            DomElement span = currentPage.getElementById("import_count");
            assertThat(span, is(notNullValue()));

            String importCount = span.getTextContent();
            assertThat(importCount, is(notNullValue()));
            assertThat(importCount.isEmpty(), is(false));
            assertThat(importCount.trim(), is("1"));

            currentPage = currentPage.getAnchorByHref(Constants.WebUI.GROUPS_VIEW_LINK).click();
            currentPage = currentPage.getAnchorByName("edit_"+groupName).click();

	        assertThat(currentPage.getAnchorByName("remove_"+ids[0]), is(notNullValue()));
            assertThat(currentPage.getAnchorByName("remove_"+ids[1]), is(notNullValue()));

	        TestUtils.logout(currentPage);
    	} finally {
            sw.close();
    	}
    }

    /**
     * Test accessing the protected areas without logging in.
     */
    @Test
    public void testCreateGroup()
        throws Exception {
        GroupTestUtils.createGroup("g"+System.currentTimeMillis());
    }
}
