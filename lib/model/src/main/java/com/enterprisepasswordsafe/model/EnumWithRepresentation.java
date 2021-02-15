package com.enterprisepasswordsafe.model;

public interface EnumWithRepresentation<T extends Enum, EnumWithRepresentation> {

    Object getRepresentation();

    T getNullValue();

    Iterable<T> values();
}
