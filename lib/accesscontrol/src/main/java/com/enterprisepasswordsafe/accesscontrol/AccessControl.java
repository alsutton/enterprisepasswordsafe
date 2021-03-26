package com.enterprisepasswordsafe.accesscontrol;


import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

public abstract class AccessControl implements Comparable<AccessControl> {

    public abstract Long getItemId();

    public abstract String getAccessorId();

    public abstract PrivateKey getModifyKey();

    public abstract PublicKey getReadKey();

    @Override
    public int compareTo(final AccessControl otherAc) {
        int itemIdComparison = getItemId().compareTo(otherAc.getItemId());
        if( itemIdComparison != 0 ) {
            return itemIdComparison;
        }

        int comparison = compareKeys(getModifyKey(), otherAc.getModifyKey());
        if (comparison != 0) {
            return comparison;
        }

        return compareKeys(getReadKey(), otherAc.getReadKey());
    }

    private int compareKeys(Key thisKey, Key otherKey) {
        if( thisKey == null) {
            return otherKey == null ? 0 : Integer.MIN_VALUE;
        }
        return otherKey == null ? Integer.MAX_VALUE : 0;
    }
}
