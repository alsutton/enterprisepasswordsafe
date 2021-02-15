package com.enterprisepasswordsafe.model.persisted;

import com.enterprisepasswordsafe.model.ReservedGroups;

import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.MapKey;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.OneToMany;
import java.util.Map;

@Entity
@DiscriminatorValue("user")
@NamedQueries(
        @NamedQuery(
                name = "Group.getByName",
                query = "SELECT g FROM Group g WHERE g.name = :name"
        )
)
public class Group extends AbstractActor {
    @OneToMany
    @MapKey(name="user")
    private Map<AbstractActor, Membership> memberships;

    public Group() {}

    public Group(String name) {
        this();
        setName(name);
    }

    public Map<AbstractActor, Membership> getMemberships() {
        return memberships;
    }

    public void setMemberships(Map<AbstractActor, Membership> memberships) {
        this.memberships = memberships;
    }

    public boolean isSystem() {
        return ReservedGroups.isSystemGroup(this);
    }
}