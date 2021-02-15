/*
 * Copyright (c) 2017 Carbon Security Ltd. <opensource@carbonsecurity.co.uk>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * EventLog.java
 *
 * Created on 08 July 2003, 16:12
 */

package com.enterprisepasswordsafe.model.persisted;

import com.enterprisepasswordsafe.model.LogEventClass;

import javax.persistence.*;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Date;

/**
 * Object representing an entry in the event log.
 */
@Entity
@Table(indexes = {
        @Index(name = "timestamp", columnList = "timestamp")
})
@NamedQueries( {
        @NamedQuery(
                name = "LogEntry.forDateRage",
                query = "SELECT l FROM LogEntry l WHERE l.timestamp >= :start AND l.timestamp <= :end"
        )
} )

public final class LogEntry {

    @Column
    @Id
    @GeneratedValue
    private Long id;

    @Column
    private LogEventClass logEventClass;

    @Column
    @Temporal(TemporalType.TIMESTAMP)
    private Date timestamp;

    @ManyToOne
    private Password item;

    @Column
    @Temporal(TemporalType.TIMESTAMP)
    private Date itemRevisionDate;

    @ManyToOne
    private User user;

    @Column
    private String event;

    @Column
    private byte[] tamperStamp;

    public LogEntry() {
        super();
    }

    public LogEntry(String event) throws GeneralSecurityException {
        this(null, null,  null, event, false);
    }

    public LogEntry(final LogEventClass logEventClass, final User user, final Password item,
                    final String event, final boolean createTamperstamp)
        throws GeneralSecurityException {
        this.logEventClass = logEventClass;
    	this.timestamp = new Date();
        this.user = user;
        this.item = item;
        this.event = event;
        tamperStamp = createTamperstamp ? calculateTamperstamp() : null;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public LogEventClass getLogEventClass() {
        return logEventClass;
    }

    public void setLogEventClass(LogEventClass logEventClass) {
        this.logEventClass = logEventClass;
    }

    public Date getTimestamp() {
        return timestamp;
    }

    public void setTimestamp(Date timestamp) {
        this.timestamp = timestamp;
    }

    public Password getItem() {
        return item;
    }

    public void setItem(Password item) {
        this.item = item;
    }

    public Date getItemRevisionDate() {
        return itemRevisionDate;
    }

    public void setItemRevisionDate(Date itemRevisionDate) {
        this.itemRevisionDate = itemRevisionDate;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public String getEvent() {
        return event;
    }

    public byte[] getTamperStamp() {
        return tamperStamp;
    }

    public byte[] calculateTamperstamp()
            throws NoSuchAlgorithmException {
        StringBuilder builder = new StringBuilder();
        if(user != null) {
            builder.append(user.getId());
            builder.append('%');
        }
        if(item != null) {
            builder.append(item.getId());
            builder.append('%');
        }
        builder.append('%');
        builder.append(event);

        MessageDigest digester = MessageDigest.getInstance("SHA256");
        return digester.digest(builder.toString().getBytes(StandardCharsets.UTF_16));
    }
}
