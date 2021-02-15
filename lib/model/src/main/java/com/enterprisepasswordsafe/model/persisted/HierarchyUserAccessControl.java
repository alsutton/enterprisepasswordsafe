package com.enterprisepasswordsafe.model.persisted;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

@Entity
public class HierarchyUserAccessControl {
    @Column
    @Id
    @GeneratedValue
    private Long id;

    @ManyToOne
    private HierarchyNode node;

    @ManyToOne
    private User user;

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

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public byte[] getSetting() {
        return setting;
    }

    public void setSetting(byte[] setting) {
        this.setting = setting;
    }
}
