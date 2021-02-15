package com.enterprisepasswordsafe.model.persisted;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Index;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.OneToMany;
import javax.persistence.Table;
import java.util.List;

@Entity
@NamedQueries({
        @NamedQuery(
                name = "AuthenticationSource.getAll",
                query = "SELECT a FROM AuthenticationSource a"
        ),
        @NamedQuery(
                name = "AuthenticationSource.getByName",
                query = "SELECT a FROM AuthenticationSource a WHERE a.name = :name"
        )
})
public class AuthenticationSource {
    @Column
    @Id
    @GeneratedValue
    private Long id;

    @Column
    private String name;

    @Column
    private String jaasType;

    @OneToMany(mappedBy = "authenticationSource", orphanRemoval = true)
    private List<AuthenticationProperty> properties;

    @OneToMany(mappedBy = "authenticationSource")
    private List<User> users;

    public AuthenticationSource() {
        super();
    }

    public AuthenticationSource(String name, String jaasType) {
        this.name = name;
        this.jaasType = jaasType;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getJaasType() {
        return jaasType;
    }

    public void setJaasType(String jaasType) {
        this.jaasType = jaasType;
    }

    public List<AuthenticationProperty> getProperties() {
        return properties;
    }

    public void setProperties(List<AuthenticationProperty> properties) {
        this.properties = properties;
    }

    public List<User> getUsers() {
        return users;
    }

    public void setUsers(List<User> users) {
        this.users = users;
    }
}
