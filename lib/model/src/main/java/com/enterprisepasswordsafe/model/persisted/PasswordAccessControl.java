package com.enterprisepasswordsafe.model.persisted;

import com.enterprisepasswordsafe.accesscontrol.AbstractAccessControl;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Transient;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.UUID;

@Entity
@NamedQueries( {
        @NamedQuery(
                name = "GroupAccessControl.getAccessControlForUserViaMemberships",
                query = "SELECT ac FROM PasswordAccessControl ac, Membership m " +
                        "WHERE m.user = :user AND m.group = ac.actor AND ac.password = :password "
        ),
        @NamedQuery(
                name = "GroupAccessControl.getAllAccessControlsForUserViaMemberships",
                query = "SELECT ac FROM PasswordAccessControl ac, Membership m " +
                        "WHERE m.user = :user AND m.group = ac.actor"
        )
} )
public class PasswordAccessControl extends AbstractAccessControl {
    @Column
    @Id
    @GeneratedValue
    private Long id;

    @ManyToOne
    private Password password;

    @ManyToOne
    private AbstractActor actor;

    @Column
    private String uuid;

    @Column
    private byte[] encryptedReadKey;

    @Column
    private byte[] encryptedModifyKey;

    @Transient
    private PublicKey readKey;

    @Transient
    private PrivateKey modifyKey;

    public PasswordAccessControl() {
        super();
    }

    public PasswordAccessControl(AbstractActor actor, Password password) {
        this.actor = actor;
        this.password = password;
    }

    public PasswordAccessControl(AbstractActor actor, Password password, PublicKey readKey, PrivateKey modifyKey) {
        this(actor, password);
        this.readKey = readKey;
        this.modifyKey = modifyKey;
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

    public AbstractActor getActor() {
        return actor;
    }

    public void setActor(AbstractActor actor) {
        this.actor = actor;
    }

    @Override
    public PublicKey getReadKey() {
        return readKey;
    }

    @Override
    public void setReadKey(PublicKey readKey) {
        this.readKey = readKey;
    }

    @Override
    public PrivateKey getModifyKey() {
        return modifyKey;
    }

    @Override
    public void setModifyKey(PrivateKey modifyKey) {
        this.modifyKey = modifyKey;
    }

    public String getUuid() {
        if (uuid == null) {
            uuid = UUID.randomUUID().toString();
        }
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    @Override
    public byte[] getEncryptedReadKey() {
        return encryptedReadKey;
    }

    @Override
    public void setEncryptedReadKey(byte[] encryptedReadKey) {
        this.encryptedReadKey = encryptedReadKey;
    }

    @Override
    public byte[] getEncryptedModifyKey() {
        return encryptedModifyKey;
    }

    @Override
    public void setEncryptedModifyKey(byte[] encryptedModifyKey) {
        this.encryptedModifyKey = encryptedModifyKey;
    }
}
