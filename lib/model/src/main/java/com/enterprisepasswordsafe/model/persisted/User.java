package com.enterprisepasswordsafe.model.persisted;

import javax.persistence.*;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Entity
@DiscriminatorValue("user")
@NamedQueries(
        @NamedQuery(
                name = "User.getByName",
                query = "SELECT u FROM User u WHERE u.name = :name"
        )
)
public class User
        extends AbstractActor {
    @Column
    private byte[] userPassword;

    @Column
    private String fullName;

    @Column
    private String email;

    @Column
    private byte[] encryptedAccessKey;

    @Column
    private byte[] encryptedAdminAccessKey;

    @Column
    @Temporal(TemporalType.TIMESTAMP)
    private Date lastLogin;

    @Column
    private Integer loginAttempts = 0;

    @ManyToOne
    private AuthenticationSource authenticationSource;

    @Column
    @Temporal(TemporalType.TIMESTAMP)
    private Date passwordLastChanged;

    @Column
    private Boolean canViewPasswords = Boolean.TRUE;

    @OneToMany(mappedBy = "requester")
    private List<RestrictedAccessRequest> restrictedAccessRequests;

    @OneToMany(mappedBy = "user")
    private List<UserIPZoneRestriction> ipZoneRestrictions;

    @OneToMany(mappedBy = "user")
    @MapKey(name = "group")
    private Map<Group, Membership> memberships;

    @OneToMany(mappedBy = "actor")
    private List<PasswordAccessControl> userAccessControls;

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

    public byte[] getEncryptedAccessKey() {
        return encryptedAccessKey;
    }

    public void setEncryptedAccessKey(byte[] encryptedAccessKey) {
        this.encryptedAccessKey = encryptedAccessKey;
    }

    public byte[] getEncryptedAdminAccessKey() {
        return encryptedAdminAccessKey;
    }

    public void setEncryptedAdminAccessKey(byte[] encryptedAdminAccessKey) {
        this.encryptedAdminAccessKey = encryptedAdminAccessKey;
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

    public Date getPasswordLastChanged() {
        return passwordLastChanged;
    }

    public void setPasswordLastChanged(Date passwordLastChanged) {
        this.passwordLastChanged = passwordLastChanged;
    }

    public Boolean getCanViewPasswords() {
        return canViewPasswords;
    }

    public void setCanViewPasswords(Boolean canViewPasswords) {
        this.canViewPasswords = canViewPasswords;
    }

    public List<RestrictedAccessRequest> getRestrictedAccessRequests() {
        return restrictedAccessRequests;
    }

    public void setRestrictedAccessRequests(List<RestrictedAccessRequest> restrictedAccessRequests) {
        this.restrictedAccessRequests = restrictedAccessRequests;
    }

    public List<UserIPZoneRestriction> getIpZoneRestrictions() {
        return ipZoneRestrictions;
    }

    public void setIpZoneRestrictions(List<UserIPZoneRestriction> ipZoneRestrictions) {
        this.ipZoneRestrictions = ipZoneRestrictions;
    }

    public Map<Group, Membership> getMemberships() {
        return memberships;
    }

    public void setMemberships(Map<Group, Membership> memberships) {
        this.memberships = memberships;
    }

    public List<PasswordAccessControl> getUserAccessControls() {
        return userAccessControls;
    }

    public void setUserAccessControls(List<PasswordAccessControl> userAccessControls) {
        this.userAccessControls = userAccessControls;
    }

}
