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

import com.enterprisepasswordsafe.htmlunit.Constants;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.html.HtmlForm;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import com.gargoylesoftware.htmlunit.html.HtmlRadioButtonInput;
import org.junit.Test;
import org.xml.sax.SAXException;

import com.enterprisepasswordsafe.htmlunit.EPSTestBase;
import com.enterprisepasswordsafe.htmlunit.TestUtils;

import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertThat;

public final class AuthsourceTests extends EPSTestBase {

    /**
     * Test creating an Active Directory Domain authentication source.
     *
     * @throws Exception Thrown if there is a problem.
     */
    @Test
    public void testAddADDomain()
        throws Exception {

    	String sourceName = "addom_" + System.currentTimeMillis();
        HtmlPage currentPage = navigateToAddPage(wc);
        currentPage = currentPage.getAnchorByText("Active Directory (using Domains)").click();

        HtmlForm form = currentPage.getFormByName("configure");
        form.getInputByName("name").setValueAttribute(sourceName);
        form.getInputByName("auth_ad.domain").setValueAttribute("TESTDOMAIN");
        form.getInputByName("auth_ad.ldaps").setValueAttribute("N");
        form.getInputByName("auth_ad.domaincontroller").setValueAttribute("TESTDC");
        currentPage = TestUtils.submit(form);

        TestUtils.checkForNoErrors(currentPage);
        TestUtils.checkPageTitle(currentPage, "Authentication Sources");

        currentPage = currentPage.getAnchorByName("edit_"+sourceName).click();

        form = currentPage.getFormByName("editform");
        assertThat(form.getInputByName("name").getValueAttribute(), is(sourceName));
        assertThat(form.getInputByName("auth_ad.domain").getValueAttribute(), is("TESTDOMAIN"));

        HtmlRadioButtonInput selectedButton = form.getCheckedRadioButton("auth_ad.ldaps");
        assertThat(selectedButton.getValueAttribute(), is("N"));
        assertThat(form.getInputByName("auth_ad.domaincontroller").getValueAttribute(), is("TESTDC"));

        TestUtils.logout(currentPage);
    }

    /**
     * Test accessing the protected areas without logging in.
     *
     * @throws Exception Thrown if there is a problem.
     */
    @Test
    public void testAddBindOnlyLDAP()
        throws Exception {
        WebClient wc = new WebClient();

    	String sourceName = "adboldap_" +System.currentTimeMillis();
        HtmlPage currentPage = navigateToAddPage(wc);
        currentPage = currentPage.getAnchorByText("Bind-Only LDAP").click();

        HtmlForm form = currentPage.getFormByName("configure");
        form.getInputByName("name").setValueAttribute(sourceName);
        form.getInputByName("auth_url").setValueAttribute("ldap://testldap:389/");
        form.getInputByName("auth_base").setValueAttribute("ou=test1, ou=test2");
        form.getInputByName("auth_prefix").setValueAttribute("cn");
        currentPage = TestUtils.submit(form);

        TestUtils.checkForNoErrors(currentPage);
        TestUtils.checkPageTitle(currentPage, "Authentication Sources");

        currentPage = currentPage.getAnchorByName("edit_"+sourceName).click();

        form = currentPage.getFormByName("editform");
        assertThat(form.getInputByName("name").getDefaultValue(), is(sourceName));
        assertThat(form.getInputByName("auth_url").getDefaultValue(), is("ldap://testldap:389/"));
        assertThat(form.getInputByName("auth_base").getDefaultValue(), is("ou=test1, ou=test2"));
        assertThat(form.getInputByName("auth_prefix").getDefaultValue(), is("cn"));

        TestUtils.logout(currentPage);
    }

    /**
     * Test accessing the protected areas without logging in.
     *
     * @throws SAXException
     * @throws IOException
     */
    @Test
    public void testAddSearchBindLDAP()
    	throws IOException, SAXException {
        WebClient wc = new WebClient();

    	String sourceName = "adsbldap_" + System.currentTimeMillis();
        HtmlPage currentPage = navigateToAddPage(wc);
        currentPage = currentPage.getAnchorByText("Search and Bind LDAP").click();

        HtmlForm form = currentPage.getFormByName("configure");
        form.getInputByName("name").setValueAttribute(sourceName);
        form.getInputByName("auth_jndi.url").setValueAttribute("ldap://testldap:389/");
        form.getInputByName("auth_jndi.search.base").setValueAttribute("ou=test1, ou=test2");
        form.getInputByName("auth_jndi.search.attr").setValueAttribute("testattr");
        currentPage = TestUtils.submit(form);

        TestUtils.checkForNoErrors(currentPage);
        TestUtils.checkPageTitle(currentPage, "Authentication Sources");

        currentPage = currentPage.getAnchorByName("edit_"+sourceName).click();

        form = currentPage.getFormByName("editform");
        assertThat(form.getInputByName("name").getDefaultValue(), is(sourceName));
        assertThat(form.getInputByName("auth_jndi.url").getDefaultValue(), is("ldap://testldap:389/"));
        assertThat(form.getInputByName("auth_jndi.search.base").getDefaultValue(), is("ou=test1, ou=test2"));
        assertThat(form.getInputByName("auth_jndi.search.attr").getDefaultValue(), is("testattr"));

        TestUtils.logout(currentPage);
    }

    /**
     * Test accessing the protected areas without logging in.
     *
     * @throws Exception Thrown if there is a problem.
     */
    @Test
    public void testAddRFC2307LDAP()
        throws Exception {
        WebClient wc = new WebClient();

    	String sourceName = "adsrfc2307_" +System.currentTimeMillis();
        HtmlPage currentPage = navigateToAddPage(wc);
        currentPage = currentPage.getAnchorByText("RFC2307 LDAP").click();

        HtmlForm form = currentPage.getFormByName("configure");
        form.getInputByName("name").setValueAttribute(sourceName);
        form.getInputByName("auth_user.provider.url").setValueAttribute("ldap://testldap:389/ou=user");
        form.getInputByName("auth_group.provider.url").setValueAttribute("ldap://testldap:389/ou=group");
        currentPage = TestUtils.submit(form);

        TestUtils.checkForNoErrors(currentPage);
        TestUtils.checkPageTitle(currentPage, "Authentication Sources");

        currentPage = currentPage.getAnchorByName("edit_"+sourceName).click();

        form = currentPage.getFormByName("editform");
        assertThat(form.getInputByName("name").getDefaultValue(), is(sourceName));
        assertThat(form.getInputByName("auth_user.provider.url").getDefaultValue(), is("ldap://testldap:389/ou=user"));
        assertThat(form.getInputByName("auth_group.provider.url").getDefaultValue(), is("ldap://testldap:389/ou=group"));

        TestUtils.logout(currentPage);
    }

    /**
     * Test accessing the protected areas without logging in.
     *
     * @throws Exception Thrown if there is a problem.
     */
    @Test
    public void testBlockDuplicateName()
        throws Exception {
        WebClient wc = new WebClient();

    	String sourceName = "authblockdup_" + System.currentTimeMillis();

        HtmlPage currentPage = navigateToAddPage(wc);
        currentPage = currentPage.getAnchorByText("RFC2307 LDAP").click();

        HtmlForm form = currentPage.getFormByName("configure");
        form.getInputByName("name").setValueAttribute(sourceName);
        form.getInputByName("auth_user.provider.url").setValueAttribute("ldap://testldap:389/ou=user");
        form.getInputByName("auth_group.provider.url").setValueAttribute("ldap://testldap:389/ou=group");
        currentPage = TestUtils.submit(form);

        TestUtils.checkForNoErrors(currentPage);
        TestUtils.checkPageTitle(currentPage, "Authentication Sources");

        sourceExistsOnPage(currentPage, sourceName);

        currentPage = currentPage.getAnchorByText("Create New Source").click();
        currentPage = currentPage.getAnchorByText("RFC2307 LDAP").click();

        form = currentPage.getFormByName("configure");
        form.getInputByName("name").setValueAttribute(sourceName);
        form.getInputByName("auth_user.provider.url").setValueAttribute("ldap://testldap:389/ou=user");
        form.getInputByName("auth_group.provider.url").setValueAttribute("ldap://testldap:389/ou=group");
        currentPage = TestUtils.submit(form);

        TestUtils.checkForError(currentPage, "There was a problem creating the authentication source.\n(A source with that name already exists).");
        TestUtils.checkPageTitle(currentPage, "Authentication Sources");

        TestUtils.logout(currentPage);
    }

    /**
     * Tests if a source exists on the authentication sources page.
     *
     * @param page A HtmlPage which should be on the Authentication Sources page.
     * @param name The name of the link.
     *
     * @return True if the source exists on the page, false if not.
     */
    private boolean sourceExistsOnPage(final HtmlPage page, final String name)
    	throws SAXException {
    	return page.getAnchorByName("edit_"+name) != null;
    }

    /**
     * Method to take the user to the add auth source page.
     *
     * @throws SAXException
     * @throws IOException
     */

    private HtmlPage navigateToAddPage(final WebClient wc)
    	throws IOException, SAXException {
        HtmlPage currentPage = TestUtils.loginAsAdmin(wc);
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.AUTH_SOURCES_LINK).click();
        currentPage = currentPage.getAnchorByHref(Constants.WebUI.AUTH_SOURCES_STAGE1_LINK).click();
    	return currentPage;
    }
}
