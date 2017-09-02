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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.URL;
import java.net.URLConnection;
import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

import com.gargoylesoftware.htmlunit.WebClient;
import org.junit.Before;
import org.junit.Test;

import static org.hamcrest.core.Is.is;
import static org.hamcrest.core.IsNull.notNullValue;
import static org.junit.Assert.assertThat;

public class RawAPITest extends EPSTestBase {

	/**
	 * The Run ID of the password
	 */

	private String passwordRunId;

    /**
     * Setup the password for the tests.
     */
    @Before
    public void setUp()
        throws IOException {
        WebClient wc = new WebClient();
        wc.getOptions().setRedirectEnabled(true);
        wc.getOptions().setJavaScriptEnabled(false);
        passwordRunId = PasswordTestUtils.createPassword(wc);
        wc.closeAllWindows();
    }

    /**
     * Test searching for a passowrd using the raw API
     *
     * @throws Exception Thrown if there is a problem.
     */
    @Test
    public void testSearch()
        throws Exception {
    	Map<String,String> params = new HashMap<String,String>();
    	params.put("username", "admin");
    	params.put("password", "admin");
    	params.put("searchUsername", "pu"+passwordRunId);
    	params.put("searchSystem", "pl"+passwordRunId);

    	String response = postData( Constants.RawAPI.FIND_IDS_ENDPOINT, params);
        assertThat(response, is(notNullValue()));
        assertThat(response.isEmpty(), is(false));
    }

    /**
     * Test creating an Active Directory Domain authentication source.
     *
     * @throws Exception Thrown if there is a problem.
     */
    @Test
    public void testSearchGetUpdateLoop()
        throws Exception {
    	Map<String,String> searchParams = new HashMap<String,String>();
    	searchParams.put("username", "admin");
    	searchParams.put("password", "admin");
    	searchParams.put("searchUsername", "pu"+passwordRunId);
    	searchParams.put("searchSystem", "pl"+passwordRunId);

    	String passwordId = postData( Constants.RawAPI.FIND_IDS_ENDPOINT, searchParams );
        assertThat(passwordId, is(notNullValue()));
        assertThat(passwordId.isEmpty(), is(false));

    	Map<String,String> getParams = new HashMap<String,String>();
    	getParams.put("username", "admin");
    	getParams.put("password", "admin");
    	getParams.put("id", passwordId);
    	String originalPassword = postData ( Constants.RawAPI.GET_PASSWORD_ENDPOINT, getParams );
        assertThat(originalPassword, is(PasswordTestUtils.DEFAULT_PASSWORD));

    	Map<String,String> updateParams = new HashMap<String,String>();
    	updateParams.put("username", "admin");
    	updateParams.put("password", "admin");
    	updateParams.put("id", passwordId);
    	updateParams.put("newPassword", "XXX");
    	String password = postData ( Constants.RawAPI.UPDATE_PASSWORD_ENDPOINT, updateParams );
        assertThat(password, is("XXX"));

    	getParams.put("id", passwordId);
    	password = postData( Constants.RawAPI.GET_PASSWORD_ENDPOINT, getParams );
        assertThat(password, is("XXX"));

    	updateParams.put("newPassword", originalPassword);
    	password = postData( Constants.RawAPI.UPDATE_PASSWORD_ENDPOINT, updateParams );
        assertThat(password, is(PasswordTestUtils.DEFAULT_PASSWORD));
    }

    /**
     * Method to post some data to a URL .
     *
     * @param url The URL to post to.
     * @param params Map containing the parameters to post.
     *
     * @return The response.
     */

    private String postData(final String url, final Map<String,String> params)
    	throws IOException {
        StringBuilder data = new StringBuilder();
    	for(Map.Entry<String, String> thisEntry: params.entrySet()) {
    		data.append(URLEncoder.encode(thisEntry.getKey(), "UTF-8"));
    		data.append('=');
    		data.append(URLEncoder.encode(thisEntry.getValue(), "UTF-8"));
    		data.append('&');
    	}
    	if( params.size() > 0 ) {
    		data.deleteCharAt(data.length()-1);
    	}

    	URL urlObject = new URL(url);
    	URLConnection conn = urlObject.openConnection();
    	conn.setDoOutput(true);
    	OutputStreamWriter wr = null;
    	BufferedReader rd = null;
    	try {
    		wr = new OutputStreamWriter(conn.getOutputStream());
    		wr.write(data.toString());
    		wr.flush();

    		rd= new BufferedReader( new InputStreamReader(conn.getInputStream()));
	    	StringBuilder response = new StringBuilder();
	    	String line;
	    	while((line = rd.readLine()) != null) {
	    		response.append(line);
	    	}

	    	return response.toString();
    	} finally {
    		if( wr != null )
    			wr.close();
    		if( rd != null )
    			rd.close();
    	}
    }


}
