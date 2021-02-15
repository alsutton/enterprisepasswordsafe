package com.enterprisepasswordsafe.model.persisted;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

@Entity
public class HierarchyGroupPasswordDefault {
    @Column
    @Id
    @GeneratedValue
    private Long id;

    @ManyToOne
    private HierarchyNode node;

    @Column
    private Character type;

    @ManyToOne
    private Group group;

    @Column
    private Character permission;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public HierarchyNode getNode() {
        return node;
    }

    public void setNode(HierarchyNode node) {
        this.node = node;
    }

    public Character getType() {
        return type;
    }

    public void setType(Character type) {
        this.type = type;
    }

    public Group getGroup() {
        return group;
    }

    public void setGroup(Group group) {
        this.group = group;
    }

    public Character getPermission() {
        return permission;
    }

    public void setPermission(Character permission) {
        this.permission = permission;
    }
}
