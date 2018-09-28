package com.enterprisepasswordsafe.engine.preferences;

import java.util.prefs.BackingStoreException;
import java.util.prefs.Preferences;

public interface PreferencesRepository {

    Preferences getPreferences();

    Preferences getFlushablePreferences();
}
