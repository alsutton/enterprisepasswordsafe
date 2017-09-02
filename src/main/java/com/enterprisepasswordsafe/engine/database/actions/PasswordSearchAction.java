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

package com.enterprisepasswordsafe.engine.database.actions;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import com.enterprisepasswordsafe.engine.database.AccessControledObject;
import com.enterprisepasswordsafe.engine.database.HierarchyNode;
import com.enterprisepasswordsafe.engine.database.HierarchyNodeDAO;
import com.enterprisepasswordsafe.engine.database.Password;
import com.enterprisepasswordsafe.engine.database.User;
import com.enterprisepasswordsafe.engine.database.actions.search.SearchTest;
import com.enterprisepasswordsafe.engine.database.derived.HierarchyNodeSummary;

/**
 * PasswordAction to handle password search requests.
 */
public class PasswordSearchAction implements NodeObjectAction {

    /**
     * The user decrypting the passwords.
     */

    private final User user;

    /**
     * The list of tests to be performed.
     */

    private final List<SearchTest> tests;

    /**
     * The matching passwords.
     */

    private final Map<String,List<Password>> results;

    /**
     * The number of matches for the search
     */

    private int resultCount;

    /**
     * Constructor. Stores the user performing the search and the search chain
     * to be matched.
     *
     * @param theUser
     *            The user performing the test.
     * @param testList
     *            The list of tests to check.
     */

    public PasswordSearchAction( final User theUser, final List<SearchTest> testList) {
        user = theUser;
        tests = testList;
        results = new HashMap<>();
        resultCount = 0;
    }

    /**
     * Process a specific password. Decrypts the passwords and then runs the
     * tests on it.
     *
     * @param node The node the password has come from.
     * @param aco The object to test if it matches the search criteria.
     *
     * @throws GeneralSecurityException Thrown if there is a problem decrypting data
     *  from the database.
     * @throws SQLException Thrown if there are problems accessing data in the database.
     * @throws UnsupportedEncodingException
     */

    @Override
	public final void process(final HierarchyNode node, final AccessControledObject aco)
        throws GeneralSecurityException, SQLException, UnsupportedEncodingException {
        if (aco == null) {
            return;
        }

        Password password = (Password) aco;
        if (!user.isAdministrator() && !password.isEnabled()) {
        	return;
        }

        for(SearchTest test : tests) {
            if (!test.matches(password)) {
                return;
            }
        }

        String nodeId = node.getNodeId();
        List<Password> theList = results.get(nodeId);
        if( theList == null ) {
        	theList = new ArrayList<>();
        	results.put(nodeId, theList);
        }
        theList.add(password);

        resultCount++;
    }

    /**
     * Get the result list.
     *
     * @return The results accumulated so far.
     */

    public final Map<HierarchyNodeSummary,List<Password>> getResults() {
        Map<HierarchyNodeSummary,List<Password>> expandedResults
                = new HashMap<HierarchyNodeSummary, List<Password>>();

        HierarchyNodeDAO hnDAO = HierarchyNodeDAO.getInstance();
        for(Map.Entry<String, List<Password>> entry : results.entrySet()) {
            try {
                HierarchyNodeSummary summary = hnDAO.getSummary(entry.getKey());
                expandedResults.put(summary, entry.getValue());
            } catch( SQLException e ) {
                Logger.getAnonymousLogger().log(Level.SEVERE, "Problem getting summary for "+entry.getKey(), e);
            }
        }

        return expandedResults;
    }

    /**
     * Get the result count.
     *
     * @return The number of matches
     */

    public final int getResultCount() {
    	return resultCount;
    }
}
