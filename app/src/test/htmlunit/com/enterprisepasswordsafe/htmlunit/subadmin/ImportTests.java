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

import com.enterprisepasswordsafe.htmlunit.*;
import com.gargoylesoftware.htmlunit.html.HtmlFileInput;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.junit.Test;

import java.io.IOException;

import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public class ImportTests extends EPSTestBase {

    @Test
    public void testImportingPassword()
        throws IOException {
    	String markerId = Long.toString(System.currentTimeMillis());

        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.PASSWORDS_IMPORT_LINK).click();
        TestUtils.checkForNoErrors(currentPage);
        TestUtils.checkPageTitle(currentPage, "Import Passwords");

        String userName = "piperm_user_"+markerId;
        String systemName = "piperm_system_"+markerId;
        currentPage = importPasswordFile(currentPage, userName, systemName);

        TestUtils.checkPageTitle(currentPage, "Results of import");

        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        currentPage = currentPage.getAnchorByText(userName).click();
        TestUtils.checkPageTitle(currentPage, "View Password");

        assertThat(currentPage.getElementById("username").getTextContent().trim(), is(userName));
        assertThat(currentPage.getElementById("system").getTextContent().trim(), is(systemName));

        TestUtils.logout(currentPage);
    }


    @Test
    public void testImportingPasswordWithSpecifiedUserPermissions()
            throws IOException {
        String permissionUser = "u_permImport" + mRunId;
        String userId = UserTestUtils.createUser(permissionUser, "2");

        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);

        String userName = "tipwsgp_user_" + mRunId;
        String systemName = "tipwsgp_system_" + mRunId;
        currentPage = importPasswordFileWithPermissions(currentPage, userName, systemName, "UM: " + permissionUser);

        TestUtils.checkPageTitle(currentPage, "Results of import");

        currentPage = assertPermissionExistsOnPassword(currentPage, userName, "u_" + userId + "_aRM");

        TestUtils.logout(currentPage);
    }

    @Test
    public void testImportingPasswordWithInheritedUserPermissions()
        throws IOException {
    	String markerId = Long.toString(System.currentTimeMillis());

        String permissionUser = "u_permImport"+markerId;
        String userId = UserTestUtils.createUser(permissionUser, "2");

        String nodeName = "piperm_node"+markerId;

        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        currentPage = HierarchyNodeUtils.createSubnode(nodeName, currentPage);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        currentPage = currentPage.getAnchorByName("edithierarchy").click();
        currentPage = currentPage.getAnchorByName("eh_dpa").click();
        HtmlForm form = currentPage.getFormByName("defaultsset");
        TestUtils.setFormParameter(form,"uperm_"+userId, "2");
        currentPage = TestUtils.submit(form);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        currentPage = currentPage.getAnchorByText(nodeName).click();

        String userName = "piperm_user_"+markerId;
        String systemName = "piperm_system_"+markerId;
        currentPage = importPasswordFile(currentPage, userName, systemName);

        currentPage = assertPermissionExistsOnPassword(currentPage, userName, "u_" + userId + "_aRM");

        TestUtils.logout(currentPage);
    }

    @Test
    public void testImportingPasswordWithSpecifiedGroupPermissions()
            throws IOException {
        String permissionGroup = "g_permImport_" + mRunId;
        String groupId = GroupTestUtils.createGroup(permissionGroup);

        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);

        String userName = "tipwsgp_user_" + mRunId;
        String systemName = "tipwsgp_system_" + mRunId;
        currentPage = importPasswordFileWithPermissions(currentPage, userName, systemName, "GM: " + permissionGroup);

        TestUtils.checkPageTitle(currentPage, "Results of import");

        currentPage = assertPermissionExistsOnPassword(currentPage, userName, "g_"+groupId+"_aRM");

        TestUtils.logout(currentPage);
    }

    @Test
    public void testImportingPasswordWithInheritedGroupPermissions()
        throws IOException {
    	String markerId = Long.toString(System.currentTimeMillis());


        String permissionGroup = "g_permImport"+markerId;
        String groupId = GroupTestUtils.createGroup(permissionGroup);

        String nodeName = "piperm_node"+markerId;

        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        currentPage = HierarchyNodeUtils.createSubnode(nodeName, currentPage);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EDIT_HIERARCHY_LINK).click();
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.NODE_PASSWORD_DEFAULTS_LINK).click();
        HtmlForm form = currentPage.getFormByName("defaultsset");
        TestUtils.setFormParameter(form,"gperm_"+groupId, "2");
        currentPage = TestUtils.submit(form);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        currentPage = currentPage.getAnchorByText(nodeName).click();

        String userName = "piperm_user_"+markerId;
        String systemName = "piperm_system_"+markerId;
        currentPage = importPasswordFile(currentPage, userName, systemName);

        TestUtils.checkPageTitle(currentPage, "Results of import");

        currentPage = assertPermissionExistsOnPassword(currentPage, userName, "g_"+groupId+"_aRM");

        TestUtils.logout(currentPage);
    }

    private HtmlPage importPasswordFile(HtmlPage currentPage, String userName, String systemName)
            throws IOException {
        String importLine = systemName + ',' + userName + ", Password, Notes";
        byte[] importData = importLine.getBytes();

        return importPasswordFile(currentPage, importData);
    }

    private HtmlPage importPasswordFileWithPermissions(final HtmlPage currentPage, final String userName,
                                                       final String systemName, final String permissions)
            throws IOException {
        String importLine = systemName + ',' + userName + ", Password, Notes, full, true, "+permissions;
        byte[] importData = importLine.getBytes();

        return importPasswordFile(currentPage, importData);
    }

    private HtmlPage importPasswordFile(HtmlPage currentPage, byte[] importData)
            throws IOException {
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.PASSWORDS_IMPORT_LINK).click();
        HtmlForm form = currentPage.getFormByName("importform");
        HtmlFileInput fileInput = form.getInputByName("file");
        fileInput.setValueAttribute("import.csv");
        fileInput.setContentType("import/csv");
        fileInput.setData(importData);
        currentPage = TestUtils.submit(form);
        TestUtils.checkForNoErrors(currentPage);
        return currentPage;
    }

    private HtmlPage assertPermissionExistsOnPassword(HtmlPage currentPage, String userName, String permission)
            throws IOException {
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.EXPLORER_LINK).click();
        currentPage = currentPage.getAnchorByText(userName).click();
        currentPage = currentPage.getAnchorByText("Alter access").click();
        HtmlForm form = currentPage.getFormByName("editaccess");
        assertThat(form.getRadioButtonsByName(permission), is(notNullValue()));

        return currentPage;
    }
}
