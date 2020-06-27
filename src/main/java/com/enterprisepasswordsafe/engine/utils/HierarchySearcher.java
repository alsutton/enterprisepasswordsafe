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

package com.enterprisepasswordsafe.engine.utils;

import com.enterprisepasswordsafe.database.AccessControledObject;
import com.enterprisepasswordsafe.database.HierarchyNode;
import com.enterprisepasswordsafe.database.HierarchyNodeDAO;
import com.enterprisepasswordsafe.database.User;
import com.enterprisepasswordsafe.database.actions.NodeObjectAction;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.logging.Level;
import java.util.logging.Logger;

public class HierarchySearcher {

    private static final int THREAD_POOL_SIZE = 10;

    public void searchHierarchy(final HierarchyNodeDAO hnDAO, final HierarchyNode node, final User theUser,
                                final NodeObjectAction action, final boolean recurse) {
        ExecutorService executorService = Executors.newFixedThreadPool(THREAD_POOL_SIZE);

        if(recurse) {
            submitChildObjectsToExecutor(executorService, hnDAO, node, theUser, action);
        } else {
            submitNodeChildrenToExecutor(executorService, hnDAO, node, theUser, action);
        }

        executorService.shutdown();
        try {
            executorService.awaitTermination(Long.MAX_VALUE, TimeUnit.MINUTES);
        } catch (InterruptedException e) {
            // Do nothing.
        }
    }

    private void submitChildObjectsToExecutor(final ExecutorService service, final HierarchyNodeDAO hnDAO,
                                              final HierarchyNode node, final User theUser, final NodeObjectAction action) {
        submitNodeChildrenToExecutor(service, hnDAO, node, theUser, action);
        try {
            for (HierarchyNode thisNode : hnDAO.getChildrenContainerNodesForUser(node, theUser, true, null)) {
                submitChildObjectsToExecutor(service, hnDAO, thisNode, theUser, action);
            }
        } catch(SQLException | GeneralSecurityException ex) {
            reportException(node, ex);
        }
    }

    private void submitNodeChildrenToExecutor(final ExecutorService service, final HierarchyNodeDAO hnDAO,
                                              final HierarchyNode node, final User theUser, final NodeObjectAction action) {
        try {
            for (final AccessControledObject aco : hnDAO.getAllChildrenObjects(node, theUser, null)) {
                Runnable nodeProcessor = () -> {
                    try {
                        action.process(node, aco);
                    } catch (Exception ex) {
                        reportException(node, ex);
                    }
                };
                service.execute(nodeProcessor);
            }
        } catch (SQLException | GeneralSecurityException | UnsupportedEncodingException e) {
            reportException(node, e);
        }
    }

    private void reportException(HierarchyNode node, Exception ex) {
        Logger.getAnonymousLogger().log(Level.SEVERE, "Problem processing node "+node.getNodeId(), ex);
    }


    private static class InstanceHolder {
        final static HierarchySearcher INSTANCE = new HierarchySearcher();
    }

    public static HierarchySearcher getInstance() {
        return InstanceHolder.INSTANCE;
    }
}
