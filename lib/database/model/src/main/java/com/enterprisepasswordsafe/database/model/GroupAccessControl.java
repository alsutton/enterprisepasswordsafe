package com.enterprisepasswordsafe.database.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

@Entity
public class GroupAccessControl {
    @Column
    @Id
    @GeneratedValue
    private Long id;

    @ManyToOne
    private Password password;

    @ManyToOne
    private Group group;

    @Column
    private byte[] readKey;

    @Column
    private byte[] modifyKey;

    @Column
    private Boolean loggable;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Password getPassword() {
        return password;
    }

    public void setPassword(Password password) {
        this.password = password;
    }

    public Group getGroup() {
        return group;
    }

    public void setGroup(Group group) {
        this.group = group;
    }

    public byte[] getReadKey() {
        return readKey;
    }

    public void setReadKey(byte[] readKey) {
        this.readKey = readKey;
    }

    public byte[] getModifyKey() {
        return modifyKey;
    }

    public void setModifyKey(byte[] modifyKey) {
        this.modifyKey = modifyKey;
    }

    public Boolean getLoggable() {
        return loggable;
    }

    public void setLoggable(Boolean loggable) {
        this.loggable = loggable;
    }
}
