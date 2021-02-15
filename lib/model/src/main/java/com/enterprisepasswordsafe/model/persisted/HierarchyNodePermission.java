package com.enterprisepasswordsafe.model.persisted;

import com.enterprisepasswordsafe.model.Permission;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

@Entity
public class HierarchyNodePermission {

    @Column
    @Id
    @GeneratedValue
    private Long id;

    @ManyToOne
    private AbstractActor actor;

    @Column
    private Permission permission;

    @ManyToOne
    private HierarchyNode node;

    public HierarchyNodePermission() {
        super();
    }

    public HierarchyNodePermission(AbstractActor actor, Permission permission, HierarchyNode node) {
        this.actor = actor;
        this.permission = permission;
        this.node = node;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public AbstractActor getActor() {
        return actor;
    }

    public void setActor(AbstractActor actor) {
        this.actor = actor;
    }

    public Permission getPermission() {
        return permission;
    }

    public void setPermission(Permission permission) {
        this.permission = permission;
    }

    public HierarchyNode getNode() {
        return node;
    }

    public void setNode(HierarchyNode node) {
        this.node = node;
    }
}
