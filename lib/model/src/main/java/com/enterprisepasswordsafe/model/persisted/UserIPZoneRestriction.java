package com.enterprisepasswordsafe.model.persisted;

import com.enterprisepasswordsafe.model.Permission;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;

@Entity
@NamedQueries({
        @NamedQuery(
                name="UserIPZoneRestriction.userAndIPAddress",
                query="SELECT u FROM UserIPZoneRestriction u WHERE u.user = :user AND u.zone.ipVersion = :ipVersion "+
                        "AND u.zone.ipStart < :ipAddress AND u.zone.ipEnd > :ipAddress"
        ),
        @NamedQuery(
                name="UserIPZoneRestriction.userAndZone",
                query="SELECT u FROM UserIPZoneRestriction u WHERE u.user = :user AND u.zone = :zone "
        )
})
public class UserIPZoneRestriction {
    @Id
    @Column
    @GeneratedValue
    private Long id;

    @ManyToOne
    private User user;

    @ManyToOne
    private IPZone zone;

    private Permission rule;

    public UserIPZoneRestriction() {
        super();
    }

    public UserIPZoneRestriction(User user, IPZone zone, Permission rule) {
        this.user = user;
        this.zone = zone;
        this.rule = rule;
    }

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

    public IPZone getZone() {
        return zone;
    }

    public void setZone(IPZone zone) {
        this.zone = zone;
    }

    public Permission getRule() {
        return rule;
    }

    public void setRule(Permission rule) {
        this.rule = rule;
    }
}
