package com.enterprisepasswordsafe.database.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;

@Entity
public class IntegrationModuleScript {

    @Column
    @Id
    @GeneratedValue
    private Long id;

    @ManyToOne
    private IntegrationModule integrationModule;

    @Column
    private String name;

    @Column
    private byte[] script;

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public IntegrationModule getIntegrationModule() {
        return integrationModule;
    }

    public void setIntegrationModule(IntegrationModule integrationModule) {
        this.integrationModule = integrationModule;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public byte[] getScript() {
        return script;
    }

    public void setScript(byte[] script) {
        this.script = script;
    }
}
