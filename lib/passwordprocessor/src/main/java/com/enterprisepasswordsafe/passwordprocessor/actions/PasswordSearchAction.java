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

package com.enterprisepasswordsafe.passwordprocessor.actions;

import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.persisted.HierarchyNode;
import com.enterprisepasswordsafe.model.persisted.Password;
import com.enterprisepasswordsafe.model.persisted.User;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;

public class PasswordSearchAction implements NodeObjectAction {

    private final List<Predicate<Password>> tests;

    private final Map<HierarchyNode,List<Password>> results;

    private int resultCount;

    private final boolean userIsAdministrator;

    public PasswordSearchAction(final DAORepository daoRepository,
                                final User theUser, final List<Predicate<Password>> testList) {
        tests = testList;
        results = new HashMap<>();
        resultCount = 0;
        userIsAdministrator = daoRepository.getMembershipDAO().isAdminUser(theUser);
    }

    @Override
	public final void process(final HierarchyNode node, final Password password) {
        if (!userIsAdministrator && !password.getEnabled()) {
        	return;
        }

        for(Predicate<Password> test : tests) {
            if (!test.test(password)) {
                return;
            }
        }

        List<Password> theList = results.computeIfAbsent(password.getParentNode(), k -> new ArrayList<>());
        theList.add(password);

        resultCount++;
    }

    public final Map<HierarchyNode,List<Password>> getResults() {
        return Map.copyOf(results);
    }

    public final int getResultCount() {
    	return resultCount;
    }
}
