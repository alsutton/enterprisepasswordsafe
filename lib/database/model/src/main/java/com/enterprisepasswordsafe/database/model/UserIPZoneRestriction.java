package com.enterprisepasswordsafe.database.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

@Entity
public class UserIPZoneRestriction {
    @Id
    @Column
    @GeneratedValue
    private Long id;

    @ManyToOne
    private User user;

    @ManyToOne
    private UserIPZone zone;

    @Column
    private Integer rule;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public UserIPZone getZone() {
        return zone;
    }

    public void setZone(UserIPZone zone) {
        this.zone = zone;
    }

    public Integer getRule() {
        return rule;
    }

    public void setRule(Integer rule) {
        this.rule = rule;
    }
}
