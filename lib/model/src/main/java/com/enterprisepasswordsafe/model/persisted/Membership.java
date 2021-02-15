package com.enterprisepasswordsafe.model.persisted;

import com.alsutton.cryptography.Decrypter;
import com.alsutton.cryptography.Encrypter;
import com.enterprisepasswordsafe.cryptography.ObjectWithEncryptableSecretKey;
import com.enterprisepasswordsafe.cryptography.ObjectWithUUID;

import javax.crypto.SecretKey;
import javax.persistence.*;
import java.security.GeneralSecurityException;
import java.util.UUID;

@Entity
@NamedQueries( {
    @NamedQuery(
            name = "Membership.getSpecificMembership",
            query = "SELECT m FROM Membership m WHERE m.user = :user AND m.group = :group"
    ),
    @NamedQuery(
            name = "Membership.getSpecificMembershipById",
            query = "SELECT m FROM Membership m WHERE m.user = :user AND m.group.id = :groupId"
    )
})
public class Membership
        extends ObjectWithEncryptableSecretKey
        implements ObjectWithUUID {
    @Column
    @Id
    @GeneratedValue
    private Long id;

    @ManyToOne
    private User user;

    @ManyToOne
    private Group group;

    @Column
    private String uuid;

    @Column
    private byte[] encryptedGroupKey;

    @Transient
    private SecretKey key;

    public Membership() {}

    public Membership(User user, Group group) {
        this.user = user;
        this.group = group;
    }

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

    public Group getGroup() {
        return group;
    }

    public void setGroup(Group group) {
        this.group = group;
    }

    public synchronized String getUuid() {
        if (uuid == null) {
            setUuid(UUID.randomUUID().toString());
        }
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    public byte[] getEncryptedGroupKey() {
        return encryptedGroupKey;
    }

    public void setEncryptedGroupKey(byte[] encryptedGroupKey) {
        this.encryptedGroupKey = encryptedGroupKey;
    }

    public SecretKey getKey() {
        return key;
    }

    public void setKey(SecretKey key) {
        this.key = key;
    }

    public void encryptGroupKey(Encrypter encrypter)
            throws GeneralSecurityException {
        byte[] encryptedKey = encryptKey(this::getKey, encrypter);
        setEncryptedGroupKey(encryptedKey);
    }

    public void decryptGroupKey(Decrypter decrypter)
            throws GeneralSecurityException {
        SecretKey decryptedKey = decryptKey(this::getEncryptedGroupKey, decrypter);
        setKey(decryptedKey);
    }
}
