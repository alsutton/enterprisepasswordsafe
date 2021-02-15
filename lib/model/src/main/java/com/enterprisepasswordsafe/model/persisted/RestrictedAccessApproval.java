package com.enterprisepasswordsafe.model.persisted;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import java.util.Date;

@Entity
public class RestrictedAccessApproval {

    @Column
    @Id
    @GeneratedValue
    private Long id;

    @ManyToOne
    private RestrictedAccessRequest request;

    @ManyToOne
    private User user;

    @Column
    private Boolean approved;

    @Column
    @Temporal(TemporalType.TIMESTAMP)
    private Date lastChanged;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public RestrictedAccessRequest getRequest() {
        return request;
    }

    public void setRequest(RestrictedAccessRequest request) {
        this.request = request;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Boolean getApproved() {
        return approved;
    }

    public void setApproved(Boolean approved) {
        this.approved = approved;
    }

    public Date getLastChanged() {
        return lastChanged;
    }

    public void setLastChanged(Date lastChanged) {
        this.lastChanged = lastChanged;
    }
}
