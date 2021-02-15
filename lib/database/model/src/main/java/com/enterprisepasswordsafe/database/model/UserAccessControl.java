package com.enterprisepasswordsafe.database.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.Table;

@Entity
public class UserAccessControl {
    @Column
    @Id
    @GeneratedValue
    private Long id;

    @ManyToOne
    private Password password;

    @ManyToOne
    private User user;

    @Column
    private byte[] readKey;

    @Column
    private byte[] modifyKey;

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

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
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
}
