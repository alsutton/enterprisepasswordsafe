package com.enterprisepasswordsafe.database.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.Temporal;
import javax.persistence.TemporalType;
import java.util.Date;

@Entity
public class EventLog {
    @Column
    @Id
    @GeneratedValue
    private Long id;

    @ManyToOne
    private User user;

    @ManyToOne
    private Password password;

    @Column
    @Temporal(TemporalType.TIMESTAMP)
    private Date itemRevisionDate;

    @Column
    @Temporal(TemporalType.TIMESTAMP)
    private Date timestamp;

    @Column
    private String event;

    @Column
    private byte[] tamperstamp;

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

    public Password getPassword() {
        return password;
    }

    public void setPassword(Password password) {
        this.password = password;
    }

    public Date getItemRevisionDate() {
        return itemRevisionDate;
    }

    public void setItemRevisionDate(Date itemRevisionDate) {
        this.itemRevisionDate = itemRevisionDate;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Date timestamp) {
        this.timestamp = timestamp;
    }

    public String getEvent() {
        return event;
    }

    public void setEvent(String event) {
        this.event = event;
    }

    public byte[] getTamperstamp() {
        return tamperstamp;
    }

    public void setTamperstamp(byte[] tamperstamp) {
        this.tamperstamp = tamperstamp;
    }
}
