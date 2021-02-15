package com.enterprisepasswordsafe.database.model;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;

@Entity
public class PasswordRestriction {

    @Column
    @Id
    @GeneratedValue
    private Long id;

    @Column
    private String name;

    @Column
    private Integer minNumeric;

    @Column
    private Integer minLower;

    @Column
    private Integer minUpper;

    @Column
    private Integer minSpecial;

    @Column
    private Integer minLength;

    @Column
    private Integer maxLength;

    @Column
    private String specialCharacters;

    @Column
    private Integer lifetime;

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

    public Integer getMinNumeric() {
        return minNumeric;
    }

    public void setMinNumeric(Integer minNumeric) {
        this.minNumeric = minNumeric;
    }

    public Integer getMinLower() {
        return minLower;
    }

    public void setMinLower(Integer minLower) {
        this.minLower = minLower;
    }

    public Integer getMinUpper() {
        return minUpper;
    }

    public void setMinUpper(Integer minUpper) {
        this.minUpper = minUpper;
    }

    public Integer getMinSpecial() {
        return minSpecial;
    }

    public void setMinSpecial(Integer minSpecial) {
        this.minSpecial = minSpecial;
    }

    public Integer getMinLength() {
        return minLength;
    }

    public void setMinLength(Integer minLength) {
        this.minLength = minLength;
    }

    public Integer getMaxLength() {
        return maxLength;
    }

    public void setMaxLength(Integer maxLength) {
        this.maxLength = maxLength;
    }

    public String getSpecialCharacters() {
        return specialCharacters;
    }

    public void setSpecialCharacters(String specialCharacters) {
        this.specialCharacters = specialCharacters;
    }

    public Integer getLifetime() {
        return lifetime;
    }

    public void setLifetime(Integer lifetime) {
        this.lifetime = lifetime;
    }
}
