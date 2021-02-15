package com.enterprisepasswordsafe.model.persisted.converters;

import com.enterprisepasswordsafe.model.AccessRoles;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

@Converter(autoApply = true)
public class AccessRoleConverter implements AttributeConverter<AccessRoles, Character> {

    @Override
    public Character convertToDatabaseColumn(AccessRoles attribute) {
        return attribute.getRepresentation();
    }

    @Override
    public AccessRoles convertToEntityAttribute(Character dbData) {
        return AccessRoles.fromRepresentation(dbData);
    }
}
