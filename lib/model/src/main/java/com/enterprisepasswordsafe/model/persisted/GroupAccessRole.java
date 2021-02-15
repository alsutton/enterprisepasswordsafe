package com.enterprisepasswordsafe.model.persisted;

import com.enterprisepasswordsafe.model.AccessRoles;

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
                name = "GroupAccessRole.getApproversForPassword",
                query = "SELECT g FROM GroupAccessRole g " +
                        "WHERE g.password = :password AND g.group.state = :state AND g.role = :role "
        ),
        @NamedQuery(
                name = "GroupAccessRole.getRolesForPasswordAndUser",
                query = "SELECT g FROM GroupAccessRole g " +
                        "WHERE g.password = :password AND g.group.membership.user = :user "+
                        "  AND g.group.state = :groupState"
        )
})
public class GroupAccessRole {
    @Column
    @Id
    @GeneratedValue
    private Long id;

    @ManyToOne
    private Group group;

    @ManyToOne
    private Password password;

    @Column
    private AccessRoles role;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Group getGroup() {
        return group;
    }

    public void setGroup(Group group) {
        this.group = group;
    }

    public Password getPassword() {
        return password;
    }

    public void setPassword(Password password) {
        this.password = password;
    }

    public AccessRoles getRole() {
        return role;
    }

    public void setRole(AccessRoles role) {
        this.role = role;
    }
}
