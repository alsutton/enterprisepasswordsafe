package com.enterprisepasswordsafe.model.persisted;

import com.enterprisepasswordsafe.model.ConfigurationOptions;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.EntityManager;
import javax.persistence.Id;

@Entity
public class ConfigurationOption {
    @Column
    @Id
    private String name;

    @Column
    private String value;

    public ConfigurationOption() {
        super();
    }

    public ConfigurationOption(String name) {
        this.name = name;
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
