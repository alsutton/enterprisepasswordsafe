package com.enterprisepasswordsafe.model.persisted.converters;

import com.enterprisepasswordsafe.model.EntityState;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

@Converter(autoApply = true)
public class EntityStateConverter implements AttributeConverter<EntityState, Integer> {

    @Override
    public Integer convertToDatabaseColumn(EntityState state) {
        return state.getRepresentation();
    }

    @Override
    public EntityState convertToEntityAttribute(Integer dbData) {
        return EntityState.fromRepresentation(dbData);
    }
}
