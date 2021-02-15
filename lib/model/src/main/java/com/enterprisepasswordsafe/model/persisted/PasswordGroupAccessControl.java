package com.enterprisepasswordsafe.model.persisted;

import javax.persistence.DiscriminatorValue;
import javax.persistence.Entity;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.Transient;
import java.security.PrivateKey;
import java.security.PublicKey;

@Entity
@DiscriminatorValue("group")
@NamedQueries( {
        @NamedQuery(
                name = "GroupAccessControl.getForGroupAndItem",
                query = "SELECT gac FROM PasswordGroupAccessControl gac WHERE gac.group = :group AND gac.password = :password"
        ),
        @NamedQuery(
                name = "GroupAccessControl.getReadAccessControl",
                query = "SELECT gac FROM PasswordGroupAccessControl gac WHERE gac.group = :group AND gac.encryptedReadKey is not null"
        ),
        @NamedQuery(
                name = "GroupAccessControl.getReadAccessControlForUser",
                query = "SELECT gac FROM PasswordGroupAccessControl gac, Membership m " +
                        "WHERE m.user = :user AND m.group = gac.group AND gac.password = :password " +
                        "  AND gac.encryptedReadKey is not null"
        ),
        @NamedQuery(
                name = "GroupAccessControl.getWriteAccessControl",
                query = "SELECT gac FROM PasswordGroupAccessControl gac WHERE gac.group = :group AND gac.encryptedModifyKey is not null"
        ),
        @NamedQuery(
                name = "GroupAccessControl.getWriteAccessControlForUser",
                query = "SELECT gac FROM PasswordGroupAccessControl gac, Membership m " +
                        "WHERE m.user = :user AND m.group = gac.group AND gac.password = :password " +
                        "  AND gac.encryptedReadKey is not null AND gac.encryptedModifyKey is not null"
        ),
} )
public class PasswordGroupAccessControl extends PasswordAccessControl {

    public PasswordGroupAccessControl() {
        super();
    }

    public PasswordGroupAccessControl(Group group, Password password, PrivateKey modifyKey, PublicKey readKey) {
        super(group, password, readKey, modifyKey);
    }

    @Transient
    public Group getGroup() {
        return (Group) getActor();
    }
}
