package com.enterprisepasswordsafe.database.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

@Entity
public class IntegrationModuleConfiguration {

    @Column
    @Id
    @GeneratedValue
    private Long id;

    @ManyToOne
    private IntegrationModuleScript script;

    @Column
    private String passwordId;

    @Column
    private String name;

    @Column
    private String value;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public IntegrationModuleScript getScript() {
        return script;
    }

    public void setScript(IntegrationModuleScript script) {
        this.script = script;
    }

    public String getPasswordId() {
        return passwordId;
    }

    public void setPasswordId(String passwordId) {
        this.passwordId = passwordId;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public String getValue() {
        return value;
    }

    public void setValue(String value) {
        this.value = value;
    }
}
