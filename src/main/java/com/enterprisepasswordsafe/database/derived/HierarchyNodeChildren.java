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

package com.enterprisepasswordsafe.database.derived;

import com.enterprisepasswordsafe.database.HierarchyNode;
import com.enterprisepasswordsafe.database.Password;

import java.util.Collection;
import java.util.Set;

/**
 * Class holding the details of the children of a HierarchyNode
 */
public class HierarchyNodeChildren {

    /**
     * The list of child container nodes.
     */

    private final Collection<HierarchyNode> nodes;

    /**
     * The set of child object nodes.
     */
    
    private Set<Password> objects;

    /**
     * Constructor, stores information.
     *
     * @param newNodes
     *            The child container nodes.
     * @param newObjects
     *            The child Object nodes.
     */

    public HierarchyNodeChildren(final Collection<HierarchyNode> newNodes, final Set<Password> newObjects) {
        nodes = newNodes;
        objects = newObjects;
    }

    /**
     * Get the List of child container nodes.
     *
     * @return The List of nodes.
     */

    public Collection<HierarchyNode> getNodes() {
        return nodes;
    }

    /**
     * Get the Set of child Objects.
     *
     * @return The Set of child Objects.
     */

    public Set<Password> getObjects() {
        return objects;
    }

    /**
     * @param newObjects The Objects to use.
     */
    public void setObjects(final Set<Password> newObjects) {
        objects = newObjects;
    }
}

