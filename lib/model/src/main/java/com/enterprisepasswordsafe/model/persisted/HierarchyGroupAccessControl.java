package com.enterprisepasswordsafe.model.persisted;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

@Entity
public class HierarchyGroupAccessControl {
    @Column
    @Id
    @GeneratedValue
    private Long id;

    @ManyToOne
    private HierarchyNode node;

    @ManyToOne
    private Group group;

    @Column
    private byte[] setting;

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

    public Group getGroup() {
        return group;
    }

    public void setGroup(Group group) {
        this.group = group;
    }

    public byte[] getSetting() {
        return setting;
    }

    public void setSetting(byte[] setting) {
        this.setting = setting;
    }
}
