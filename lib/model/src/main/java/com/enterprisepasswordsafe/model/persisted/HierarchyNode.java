package com.enterprisepasswordsafe.model.persisted;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.MapKey;
import javax.persistence.NamedQueries;
import javax.persistence.NamedQuery;
import javax.persistence.OneToMany;
import java.util.Map;

@Entity
@NamedQueries({
        @NamedQuery(
                name = "HierarchyNode.getPasswordsAccessibleViaUACForUser",
                query = "SELECT p FROM PasswordAccessControl pac, Password p " +
                        "WHERE pac.actor = :user AND pac.password = p " +
                        "  AND p.parentNode = :node AND pac.encryptedReadKey is not null"
        ),
        @NamedQuery(
                name = "HierarchyNode.getPasswordsAccessibleViaGACForUser",
                query = "SELECT p FROM PasswordAccessControl pac, Membership m, Password p " +
                        "WHERE m.user = :user AND m.group = pac.actor AND pac.password = p " +
                        "  AND p.parentNode = :node AND pac.encryptedReadKey is not null"
        )
})
public class HierarchyNode {
    @Column
    @Id
    @GeneratedValue
    private Long id;

    @Column
    private String name;

    @ManyToOne
    private HierarchyNode parent;

    @ManyToOne
    private User owner;

    @OneToMany(mappedBy = "parent", cascade = CascadeType.REMOVE)
    @MapKey(name="name")
    private Map<String,HierarchyNode> children;

    @OneToMany(cascade = CascadeType.REMOVE)
    @MapKey(name="id")
    private Map<Long,Password> passwords;

    @OneToMany(cascade = CascadeType.REMOVE)
    @MapKey(name="actor")
    private Map<AbstractActor,HierarchyNodePermission> defaultPermissions;

    @OneToMany(cascade = CascadeType.REMOVE)
    @MapKey(name="actor")
    private Map<AbstractActor,HierarchyNodeAccessRule> accessRules;

    public HierarchyNode() {
        super();
    }

    public HierarchyNode(HierarchyNode parent, String name) {
        this.parent = parent;
        this.name = name;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public HierarchyNode getParent() {
        return parent;
    }

    public void setParent(HierarchyNode parent) {
        this.parent = parent;
    }

    public Map<String,HierarchyNode> getChildren() {
        return children;
    }

    public void setChildren(Map<String,HierarchyNode> children) {
        this.children = children;
    }

    public Map<Long,Password> getPasswords() {
        return passwords;
    }

    public void setPasswords(Map<Long,Password> passwords) {
        this.passwords = passwords;
    }

    public User getOwner() {
        return owner;
    }

    public void setOwner(User owner) {
        this.owner = owner;
    }

    public Map<AbstractActor, HierarchyNodePermission> getDefaultPermissions() {
        return defaultPermissions;
    }

    public void setDefaultPermissions(Map<AbstractActor, HierarchyNodePermission> defaultPermissions) {
        this.defaultPermissions = defaultPermissions;
    }

    public Map<AbstractActor, HierarchyNodeAccessRule> getAccessRules() {
        return accessRules;
    }

    public void setAccessRules(Map<AbstractActor, HierarchyNodeAccessRule> accessRules) {
        this.accessRules = accessRules;
    }
}
