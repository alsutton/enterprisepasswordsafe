package com.enterprisepasswordsafe.model.persisted;

import com.enterprisepasswordsafe.cryptography.ObjectWithEncryptableSecretKey;
import com.enterprisepasswordsafe.cryptography.ObjectWithSecretKey;
import com.enterprisepasswordsafe.cryptography.ObjectWithUUID;
import com.enterprisepasswordsafe.model.EntityState;
import com.enterprisepasswordsafe.model.EntityWithId;
import com.enterprisepasswordsafe.model.EntityWithName;

import javax.crypto.SecretKey;
import javax.persistence.*;
import java.util.UUID;

/**
 * Abstract class representing an actor (i.e. user or group).
 */
@Entity
@Inheritance(strategy = InheritanceType.TABLE_PER_CLASS)
@DiscriminatorColumn(name="actor_type")
public abstract class AbstractActor
    extends ObjectWithEncryptableSecretKey
    implements EntityWithId, EntityWithName, ObjectWithUUID, ObjectWithSecretKey {
    @Column
    @Id
    @GeneratedValue
    private Long id;

    @Column
    private String uuid = UUID.randomUUID().toString();

    @Column(unique = true)
    private String name;

    @Column
    private EntityState state;

    @Transient
    private SecretKey key;

    @Override
    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getUuid() {
        return uuid;
    }

    public void setUuid(String uuid) {
        this.uuid = uuid;
    }

    @Override
    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public EntityState getState() {
        return state;
    }

    public void setState(EntityState state) {
        this.state = state;
    }

    public SecretKey getKey() {
        return key;
    }

    public void setKey(SecretKey key) {
        this.key = key;
    }
}
