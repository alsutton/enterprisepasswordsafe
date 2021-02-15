package com.enterprisepasswordsafe.model;

public enum LogEventClass {
    AUTHENTICATION(1, "authentication"),
    CONFIGURATION(2, "configuration"),
    REPORTS(3, "reports"),
    USER_MANIPULATION(4, "user_manipulation"),
    GROUP_MANIPULATION(5, "group_manipulation"),
    OBJECT_MANIPULATION(6, "object_manipulation"),
    HIERARCHY_MANIPULATION(7, "hierarchy_manipulation");

    private final int representation;
    private final String configurationSuffix;

    LogEventClass(int representation, String configurationSuffix) {
        this.representation = representation;
        this.configurationSuffix = configurationSuffix;
    }

    public int getRepresentation() {
        return representation;
    }

    public String getConfigurationSuffix() {
        return configurationSuffix;
    }

    public static String getEmailPropertyFor(LogEventClass logEventClass) {
        if(logEventClass == null) {
            return ConfigurationOptions.SMTP_TO_PROPERTY.getPropertyName();
        }
        StringBuilder propertyName = new StringBuilder(ConfigurationOptions.SMTP_TO_PROPERTY.getPropertyName());
        propertyName.append('.');
        propertyName.append(logEventClass.getConfigurationSuffix());
        return propertyName.toString();
    }

    public static LogEventClass fromRepresentation(int representation) {
        for(LogEventClass thisClass : values()) {
            if(thisClass.getRepresentation() == representation) {
                return thisClass;
            }
        }
        throw new RuntimeException("Unable to find log event class for "+representation);
    }
}
