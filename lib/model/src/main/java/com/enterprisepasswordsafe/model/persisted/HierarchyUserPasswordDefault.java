package com.enterprisepasswordsafe.model.persisted;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

@Entity
public class HierarchyUserPasswordDefault {
    @Column
    @Id
    @GeneratedValue
    private Long id;

    @ManyToOne
    private HierarchyNode node;

    @Column
    private Character type;

    @ManyToOne
    private User user;

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

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Character getPermission() {
        return permission;
    }

    public void setPermission(Character permission) {
        this.permission = permission;
    }
}
