package com.enterprisepasswordsafe.database.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.Table;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import javax.persistence.UniqueConstraint;
import java.util.Date;

@Entity
@Table(uniqueConstraints = { @UniqueConstraint(columnNames = "name")})
public class User {
    @Column
    @Id
    @GeneratedValue
    private Long id;

    @Column(name="name")
    private String name;

    @Column
    private byte[] userPassword;

    @Column
    private String fullName;

    @Column
    private String email;

    @Column
    private byte[] accessKey;

    @Column
    private byte[] adminAccessKey;

    @Column
    @Temporal(TemporalType.TIMESTAMP)
    private Date lastLogin;

    @Column
    private Integer loginAttempts;

    @ManyToOne
    private AuthenticationSource authenticationSource;

    @Column
    private Boolean disabled;

    @Column
    @Temporal(TemporalType.TIMESTAMP)
    private Date passwordLastChanged;

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

    public byte[] getUserPassword() {
        return userPassword;
    }

    public void setUserPassword(byte[] userPassword) {
        this.userPassword = userPassword;
    }

    public String getFullName() {
        return fullName;
    }

    public void setFullName(String fullName) {
        this.fullName = fullName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    public byte[] getAccessKey() {
        return accessKey;
    }

    public void setAccessKey(byte[] accessKey) {
        this.accessKey = accessKey;
    }

    public byte[] getAdminAccessKey() {
        return adminAccessKey;
    }

    public void setAdminAccessKey(byte[] adminAccessKey) {
        this.adminAccessKey = adminAccessKey;
    }

    public Date getLastLogin() {
        return lastLogin;
    }

    public void setLastLogin(Date lastLogin) {
        this.lastLogin = lastLogin;
    }

    public Integer getLoginAttempts() {
        return loginAttempts;
    }

    public void setLoginAttempts(Integer loginAttempts) {
        this.loginAttempts = loginAttempts;
    }

    public AuthenticationSource getAuthenticationSource() {
        return authenticationSource;
    }

    public void setAuthenticationSource(AuthenticationSource authenticationSource) {
        this.authenticationSource = authenticationSource;
    }

    public Boolean getDisabled() {
        return disabled;
    }

    public void setDisabled(Boolean disabled) {
        this.disabled = disabled;
    }

    public Date getPasswordLastChanged() {
        return passwordLastChanged;
    }

    public void setPasswordLastChanged(Date passwordLastChanged) {
        this.passwordLastChanged = passwordLastChanged;
    }
}
