package com.enterprisepasswordsafe.engine.preferences;

import java.util.prefs.Preferences;

public class UserPreferencesRepository
    implements PreferencesRepository {
    @Override
    public Preferences getPreferences() {
        return Preferences.userRoot();
    }

    @Override
    public Preferences getFlushablePreferences() {
        return getPreferences();
    }

}
