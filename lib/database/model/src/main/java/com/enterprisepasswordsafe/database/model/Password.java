package com.enterprisepasswordsafe.database.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToMany;
import javax.persistence.ManyToOne;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import java.util.Date;
import java.util.List;

@Entity
public class Password {
    @Column
    @Id
    @GeneratedValue
    private Long id;

    @ManyToOne
    private Location location;

    @Column
    @Temporal(TemporalType.DATE)
    private Date expiry;

    @Column
    private Boolean enabled;

    @Column
    private Boolean audited;

    @Column
    private Boolean historyStored;

    @Column
    private Boolean restrictedAccessEnabled;

    @Column
    private Integer type;

    @Column
    @Temporal(TemporalType.DATE)
    private Date lastChanged;

    @Column
    private byte[] data;

    @ManyToOne
    private PasswordRestriction passwordRestriction;

    @ManyToMany
    private List<User> restrictedAccessApprovers;

    @ManyToMany
    private List<User> restrictedAccessBlockers;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Location getLocation() {
        return location;
    }

    public void setLocation(Location location) {
        this.location = location;
    }

    public Date getExpiry() {
        return expiry;
    }

    public void setExpiry(Date expiry) {
        this.expiry = expiry;
    }

    public Boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    public Boolean getAudited() {
        return audited;
    }

    public void setAudited(Boolean audited) {
        this.audited = audited;
    }

    public Boolean getHistoryStored() {
        return historyStored;
    }

    public void setHistoryStored(Boolean historyStored) {
        this.historyStored = historyStored;
    }

    public Boolean getRestrictedAccessEnabled() {
        return restrictedAccessEnabled;
    }

    public void setRestrictedAccessEnabled(Boolean restrictedAccessEnabled) {
        this.restrictedAccessEnabled = restrictedAccessEnabled;
    }

    public Integer getType() {
        return type;
    }

    public void setType(Integer type) {
        this.type = type;
    }

    public Date getLastChanged() {
        return lastChanged;
    }

    public void setLastChanged(Date lastChanged) {
        this.lastChanged = lastChanged;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
    }

    public PasswordRestriction getPasswordRestriction() {
        return passwordRestriction;
    }

    public void setPasswordRestriction(PasswordRestriction passwordRestriction) {
        this.passwordRestriction = passwordRestriction;
    }

    public List<User> getRestrictedAccessApprovers() {
        return restrictedAccessApprovers;
    }

    public void setRestrictedAccessApprovers(List<User> restrictedAccessApprovers) {
        this.restrictedAccessApprovers = restrictedAccessApprovers;
    }

    public List<User> getRestrictedAccessBlockers() {
        return restrictedAccessBlockers;
    }

    public void setRestrictedAccessBlockers(List<User> restrictedAccessBlockers) {
        this.restrictedAccessBlockers = restrictedAccessBlockers;
    }
}
