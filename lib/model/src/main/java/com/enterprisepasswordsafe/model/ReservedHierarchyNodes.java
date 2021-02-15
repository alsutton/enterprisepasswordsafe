package com.enterprisepasswordsafe.model;

import com.enterprisepasswordsafe.model.persisted.HierarchyNode;

public enum ReservedHierarchyNodes {
    SYSTEM_ROOT(0L);

    private Long id;

    ReservedHierarchyNodes(Long id) {
        this.id = id;
    }

    public Long getId() {
        return id;
    }

    public boolean matches(HierarchyNode node) {
        return node != null && id.equals(node.getId());
    }
}
