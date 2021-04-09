/*
 * Copyright (c) 2017 Carbon Security Ltd. <opensource@carbonsecurity.co.uk>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package com.enterprisepasswordsafe.engine.utils;

import com.enterprisepasswordsafe.model.persisted.PasswordRestriction;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class PasswordRestrictionUtils
        implements Serializable {

    private static final String NO_LIMITS_STRING = "There are no restrictions on the contents of the password.";

    public static final String NUMERIC_PASSWORD_CHARS = "1234567890";

    public static final String LOWER_PASSWORD_CHARS = "abcdefghijklmnopqrstuvwxyz";

    public static final String UPPER_PASSWORD_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    public static final String MIGRATED_RESTRICTION_ID = "-2";

    public static final String LOGIN_PASSWORD_RESTRICTION_ID = "-1";


    /**
     * Verify a password meets the current password policy.
     *
     * @param password The password to check.
     * @return true if the password meets the policy, false if not.
     */

    public boolean verify(PasswordRestriction restriction, final String password) {
        int passwordLength = password.length();
        if (passwordLength < restriction.getMinLength() || passwordLength > restriction.getMaxLength()) {
            return false;
        }
        return meetsCharacterBasedRequirements(restriction, password);
    }

    private boolean meetsCharacterBasedRequirements(PasswordRestriction restriction, final String password) {
        int special = 0, numeric = 0, upper = 0, lower = 0;

        for (int i = 0; i < password.length(); i++) {
            char thisChar = password.charAt(i);
            if (LOWER_PASSWORD_CHARS.indexOf(thisChar) != -1) {
                lower++;
            } else if (UPPER_PASSWORD_CHARS.indexOf(thisChar) != -1) {
                upper++;
            } else if (NUMERIC_PASSWORD_CHARS.indexOf(thisChar) != -1) {
                numeric++;
            }
            if (restriction.getSpecialCharacters().indexOf(thisChar) != -1) {
                special++;
            }
        }

        return (special >= restriction.getMinSpecial())
                && (numeric >= restriction.getMinNumeric())
                && (lower >= restriction.getMinLower())
                && (upper >= restriction.getMinUpper());
    }

    public boolean isRestrictive(PasswordRestriction restriction) {
        return  restriction.getMinSpecial() > 0
                || restriction.getMinNumeric() > 0
                || restriction.getMinLower() > 0
                || restriction.getMinUpper() > 0
        || restriction.getMinLength() > restriction.getMinUpper() + restriction.getMinLower() +
                                        restriction.getMinNumeric() + restriction.getMinSpecial();
    }

    public String toString(PasswordRestriction passwordRestriction) {
        List<String> sections = getEnabledSettingsStrings(passwordRestriction);
        if (sections.isEmpty()) {
            return NO_LIMITS_STRING;
        }

        int sectionCount = sections.size();
        StringBuilder description = new StringBuilder();
        description.append("The password must have at least ");
        for (int i = 0; i < sectionCount - 1; i++) {
            description.append(sections.get(i));
            description.append(", ");
        }
        if (sectionCount > 1) {
            description.append("and ");
        }
        description.append(sections.get(sectionCount - 1));
        if (sectionCount > 1) {
            description.append(", and");
        }
        description.append(" at most ");
        description.append(passwordRestriction.getMaxLength());
        description.append(" characters in total");

        return description.toString();
    }

    private List<String> getEnabledSettingsStrings(PasswordRestriction restriction) {
        List<String> sections = new ArrayList<>();
        int minSpecial = restriction.getMinSpecial();
        addSectionIfNeeded(sections, minSpecial,
                minSpecial+" non alpha-numeric "+getCharactersPhrase(minSpecial)+
                        " from the set '" +restriction.getSpecialCharacters()+ "'");
        int minNumeric = restriction.getMinNumeric();
        addSectionIfNeeded(sections, minNumeric,minNumeric + " numeric " + getCharactersPhrase(minNumeric));
        int minLower = restriction.getMinLower();
        addSectionIfNeeded(sections, minLower, minLower+" lower case "+getCharactersPhrase(minLower));
        int minUpper = restriction.getMinUpper();
        addSectionIfNeeded(sections, minUpper, minUpper+" upper case "+getCharactersPhrase(minUpper));
        int minLength = restriction.getMinLength();
        addSectionIfNeeded(sections, minLength > minUpper + minLower + minNumeric + minSpecial,
                minLength+" "+getCharactersPhrase(minLength)+" in total");
        return sections;
    }

    private void addSectionIfNeeded(List<String> enabledSettings, int setting, String text) {
        addSectionIfNeeded(enabledSettings, setting > 0, text);
    }

    private void addSectionIfNeeded(List<String> enabledSettings, boolean isNeeded, String text) {
        if (isNeeded) {
            enabledSettings.add(text);
        }
    }

    private String getCharactersPhrase(int count) {
        return count == 1 ? "character" : "characters";
    }

    public static class Summary {

        public final String id;

        public final String name;

        Summary(String newId, String newName) {
            id = newId;
            name = newName;
        }

        public String getId() {
            return this.id;
        }

        public String getName() {
            return this.name;
        }
    }
}
