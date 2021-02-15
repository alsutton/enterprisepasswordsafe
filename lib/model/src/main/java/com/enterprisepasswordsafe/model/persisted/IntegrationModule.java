package com.enterprisepasswordsafe.model.persisted;

import javax.persistence.CascadeType;
import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.OneToMany;
import java.util.List;

@Entity
public class IntegrationModule {
    @Column
    @Id
    @GeneratedValue
    private Long id;

    @Column
    private String name;

    @Column
    private String className;

    @OneToMany(cascade = {CascadeType.REMOVE, CascadeType.DETACH})
    private List<IntegrationModuleScript> scripts;

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

    public String getClassName() {
        return className;
    }

    public void setClassName(String className) {
        this.className = className;
    }

    public List<IntegrationModuleScript> getScripts() {
        return scripts;
    }

    public void setScripts(List<IntegrationModuleScript> scripts) {
        this.scripts = scripts;
    }
}
