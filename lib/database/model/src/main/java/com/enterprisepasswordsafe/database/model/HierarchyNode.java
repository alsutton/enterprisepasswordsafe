package com.enterprisepasswordsafe.database.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.OneToMany;
import java.util.List;

@Entity
public class HierarchyNode {
    @Column
    @Id
    @GeneratedValue
    private Long id;

    @Column
    private String name;

    @Column
    private Integer type;

    @ManyToOne
    private HierarchyNode parent;

    @OneToMany(mappedBy = "parent")
    private List<HierarchyNode> children;

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

    public Integer getType() {
        return type;
    }

    public void setType(Integer type) {
        this.type = type;
    }

    public HierarchyNode getParent() {
        return parent;
    }

    public void setParent(HierarchyNode parent) {
        this.parent = parent;
    }

    public List<HierarchyNode> getChildren() {
        return children;
    }

    public void setChildren(List<HierarchyNode> children) {
        this.children = children;
    }
}
