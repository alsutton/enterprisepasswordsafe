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
                name = "UserAccessRole.getApproversForPassword",
                query = "SELECT u FROM UserAccessRole u " +
                        "WHERE u.password = :password AND u.user.state = :state AND u.role = :role"
        ),
        @NamedQuery(
                name = "UserAccessRole.getRoleForPasswordAndUser",
                query = "SELECT u FROM UserAccessRole u " +
                        "WHERE u.password = :password AND u.user = :user"
        )
})
public class UserAccessRole {
    @Column
    @Id
    @GeneratedValue
    private Long id;

    @ManyToOne
    private Password password;

    @ManyToOne
    private User user;

    @Column
    private AccessRoles role;

    public UserAccessRole() {
        super();
    }

    public UserAccessRole(User user, Password password, AccessRoles role) {
        this.user = user;
        this.password = password;
        this.role = role;
    }

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

    public AccessRoles getRole() {
        return role;
    }

    public void setRole(AccessRoles role) {
        this.role = role;
    }
}
