package com.enterprisepasswordsafe.model.persisted;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import javax.persistence.OneToOne;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import java.util.Date;
import java.util.List;

@Entity(name="ra_requests")
public class RestrictedAccessRequest {

    @Column
    @Id
    @GeneratedValue
    private Long id;

    @OneToOne
    private Password password;

    @Column
    @Temporal(TemporalType.TIMESTAMP)
    private Date requestTimestamp;

    @Column
    @Temporal(TemporalType.TIMESTAMP)
    private Date viewedTimestamp;

    @Column(name="reason")
    private String name;

    @ManyToOne
    private User requester;

    @OneToMany(mappedBy = "request")
    private List<RestrictedAccessApproval> approvals;

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

    public Date getRequestTimestamp() {
        return requestTimestamp;
    }

    public void setRequestTimestamp(Date requestTimestamp) {
        this.requestTimestamp = requestTimestamp;
    }

    public Date getViewedTimestamp() {
        return viewedTimestamp;
    }

    public void setViewedTimestamp(Date viewedTimestamp) {
        this.viewedTimestamp = viewedTimestamp;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public User getRequester() {
        return requester;
    }

    public void setRequester(User requester) {
        this.requester = requester;
    }

    public List<RestrictedAccessApproval> getApprovals() {
        return approvals;
    }

    public void setApprovals(List<RestrictedAccessApproval> approvals) {
        this.approvals = approvals;
    }
}
