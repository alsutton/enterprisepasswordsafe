package com.enterprisepasswordsafe.model.persisted;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.ManyToOne;
import javax.persistence.OneToOne;

@Entity
public class IntegrationModuleConfiguration {

    @Column
    @Id
    @GeneratedValue
    private Long id;

    @ManyToOne
    private IntegrationModuleScript script;

    @OneToOne
    private Password password;

    @Column
    private String name;

    @Column
    private String value;

    public IntegrationModuleConfiguration() {
        super();
    }

    public IntegrationModuleConfiguration(IntegrationModuleScript script, Password password,
                                          String name, String value) {
        this.script = script;
        this.password = password;
        this.name = name;
        this.value = value;
    }

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

    public Password getPassword() {
        return password;
    }

    public void setPassword(Password password) {
        this.password = password;
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
