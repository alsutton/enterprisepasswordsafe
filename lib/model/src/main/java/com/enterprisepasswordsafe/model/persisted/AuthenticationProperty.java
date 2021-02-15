package com.enterprisepasswordsafe.model.persisted;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

@Entity
public class AuthenticationProperty {
    @Column
    @Id
    @GeneratedValue
    private Long id;

    @ManyToOne
    private AuthenticationSource authenticationSource;

    @Column
    private String name;

    @Column
    private String value;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public AuthenticationProperty() {
        super();
    }

    public AuthenticationProperty(String name, String value) {
        this.name = name;
        this.value = value;
    }

    public AuthenticationSource getAuthenticationSource() {
        return authenticationSource;
    }

    public void setAuthenticationSource(AuthenticationSource authenticationSource) {
        this.authenticationSource = authenticationSource;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
