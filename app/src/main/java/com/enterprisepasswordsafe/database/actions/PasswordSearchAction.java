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

package com.enterprisepasswordsafe.database.actions;

import com.enterprisepasswordsafe.database.derived.HierarchyNodeSummary;
import com.enterprisepasswordsafe.engine.hierarchy.Summaries;
import com.enterprisepasswordsafe.engine.users.UserClassifier;
import com.enterprisepasswordsafe.model.AccessControledObject;
import com.enterprisepasswordsafe.model.persisted.HierarchyNode;
import com.enterprisepasswordsafe.model.persisted.Password;
import com.enterprisepasswordsafe.model.persisted.User;

import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.logging.Level;
import java.util.logging.Logger;

public class PasswordSearchAction implements NodeObjectAction {

    private final List<Predicate<Password>> tests;

    private final Map<String,List<Password>> results;

    private int resultCount;

    private final boolean userIsAdministrator;

    private final Summaries summaries = new Summaries();

    public PasswordSearchAction(final User theUser, final List<Predicate<Password>> testList)
            throws SQLException {
        tests = testList;
        results = new HashMap<>();
        resultCount = 0;
        userIsAdministrator = new UserClassifier().isAdministrator(theUser);
    }

    @Override
	public final void process(final HierarchyNode node, final Password password) {
        if (aco == null) {
            return;
        }

        Password password = (Password) aco;
        if (!userIsAdministrator && !password.isEnabled()) {
        	return;
        }

        for(Predicate<Password> test : tests) {
            if (!test.test(password)) {
                return;
            }
        }

        String nodeId = node.getNodeId();
        List<Password> theList = results.computeIfAbsent(nodeId, k -> new ArrayList<>());
        theList.add(password);

        resultCount++;
    }

    public final Map<HierarchyNodeSummary,List<Password>> getResults() {
        Map<HierarchyNodeSummary,List<Password>> expandedResults = new HashMap<>();
        for(Map.Entry<String, List<Password>> entry : results.entrySet()) {
            try {
                HierarchyNodeSummary summary = summaries.getSummary(entry.getKey());
                expandedResults.put(summary, entry.getValue());
            } catch( SQLException e ) {
                Logger.getAnonymousLogger().log(Level.SEVERE, "Problem getting summary for "+entry.getKey(), e);
            }
        }

        return expandedResults;
    }

    public final int getResultCount() {
    	return resultCount;
    }
}
