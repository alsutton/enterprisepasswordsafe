package com.enterprisepasswordsafe.model.persisted.converters;

import com.enterprisepasswordsafe.model.Permission;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

@Converter(autoApply = true)
public class RestrictionConverter implements AttributeConverter<Permission, String> {

    @Override
    public String convertToDatabaseColumn(Permission attribute) {
        return attribute.getRepresentation();
    }

    @Override
    public Permission convertToEntityAttribute(String dbData) {
        return Permission.fromRepresentation(dbData);
    }
}
