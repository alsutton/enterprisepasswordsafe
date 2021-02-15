package com.enterprisepasswordsafe.engine.accesscontrol;

import java.security.PrivateKey;
import java.security.PublicKey;

public abstract class AccessControlBuilder<T extends AccessControl> {
    String itemId;
    String accessorId;
    PrivateKey modifyKey;
    PublicKey readKey;

    public AccessControlBuilder<T> withItemId(String itemId) {
        this.itemId = itemId;
        return this;
    }

    public AccessControlBuilder<T> withAccessorId(String accessorId) {
        this.accessorId = accessorId;
        return this;
    }

    public AccessControlBuilder<T> withModifyKey(PrivateKey modifyKey) {
        this.modifyKey = modifyKey;
        return this;
    }

    public AccessControlBuilder<T> withReadKey(PublicKey readKey) {
        this.readKey = readKey;
        return this;
    }

    public AccessControlBuilder<T> copyFrom(AccessControl original) {
        if(original != null) {
            withItemId(original.getItemId());
            withAccessorId(original.getAccessorId());
            withModifyKey(original.getModifyKey());
            withReadKey(original.getReadKey());
        }
        return this;
    }

    public abstract T build();
}
