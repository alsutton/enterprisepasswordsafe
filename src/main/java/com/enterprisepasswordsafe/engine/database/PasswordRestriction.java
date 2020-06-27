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

package com.enterprisepasswordsafe.engine.database;

import java.io.Serializable;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import com.enterprisepasswordsafe.engine.utils.IDGenerator;

public class PasswordRestriction
        implements Serializable {

    private static final String NO_LIMITS_STRING = "There are no restrictions on the contents of the password.";

    public static final String NUMERIC_PASSWORD_CHARS = "1234567890";

    public static final String LOWER_PASSWORD_CHARS = "abcdefghijklmnopqrstuvwxyz";

    public static final String UPPER_PASSWORD_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    public static final String MIGRATED_RESTRICTION_ID = "-2";

    public static final String LOGIN_PASSWORD_RESTRICTION_ID = "-1";

    private String restrictionId;

    private String name;

    private int minNumeric;

    private int minLower;

    private int minUpper;

    private int minSpecial;

    private int minLength;

    private int maxLength;

    private String specialCharacters;

    private int lifetime;

    public PasswordRestriction(final String theName, final int theMinLower,
                               final int theMinUpper, final int theMinNumeric, final int theMinSpecial,
                               final int theMinLength, final int theMaxLength, final String theSpecial,
                               final int theLifetime) {
        restrictionId = IDGenerator.getID();
        name = theName;
        minLower = theMinLower;
        minUpper = theMinUpper;
        minNumeric = theMinNumeric;
        minSpecial = theMinSpecial;
        minLength = theMinLength;
        maxLength = theMaxLength;
        specialCharacters = theSpecial;
        lifetime = theLifetime;
    }

    public PasswordRestriction(final ResultSet rs)
            throws SQLException {
        restrictionId = rs.getString(1);
        name = rs.getString(2);
        minNumeric = rs.getInt(3);
        minLower = rs.getInt(4);
        minUpper = rs.getInt(5);
        minSpecial = rs.getInt(6);
        minLength = rs.getInt(7);
        specialCharacters = rs.getString(8);
        lifetime = rs.getInt(9);
        if (rs.wasNull()) {
            lifetime = 0;
        }
        maxLength = rs.getInt(10);
        if (rs.wasNull()) {
            maxLength = minLength + 16;
        }
    }

    /**
     * Verify a password meets the current password policy.
     *
     * @param password The password to check.
     * @return true if the password meets the policy, false if not.
     */

    public boolean verify(final String password) {
        int passwordLength = password.length();
        if (passwordLength < minLength || passwordLength > maxLength) {
            return false;
        }
        return meetsCharacterBasedRequirements(password);
    }

    private boolean meetsCharacterBasedRequirements(final String password) {
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
            if (specialCharacters.indexOf(thisChar) != -1) {
                special++;
            }
        }

        return (special >= minSpecial) && (numeric >= minNumeric)
                && (lower >= minLower) && (upper >= minUpper);
    }

    public int getMinLength() {
        return minLength;
    }

    public int getMinLower() {
        return minLower;
    }

    public int getMinNumeric() {
        return minNumeric;
    }

    public int getMinSpecial() {
        return minSpecial;
    }

    public int getMinUpper() {
        return minUpper;
    }

    public String getName() {
        return name;
    }

    public int getLifetime() {
        return lifetime;
    }

    public void setLifetime(int newLifetime) {
        lifetime = newLifetime;
    }

    public void setId(String newId) {
        restrictionId = newId;
    }

    public String getId() {
        return restrictionId;
    }

    public String getSpecialCharacters() {
        return specialCharacters;
    }

    public void setMinLength(int minLength) {
        this.minLength = minLength;
    }

    public void setMinLower(int minLower) {
        this.minLower = minLower;
    }

    public void setMinNumeric(int minNumeric) {
        this.minNumeric = minNumeric;
    }

    public void setMinSpecial(int minSpecial) {
        this.minSpecial = minSpecial;
    }

    public void setMinUpper(int minUpper) {
        this.minUpper = minUpper;
    }

    public void setName(String name) {
        this.name = name;
    }

    public void setSpecialCharacters(String specialCharacters) {
        this.specialCharacters = specialCharacters;
    }

    public int getMaxLength() {
        return maxLength;
    }

    public void setMaxLength(int maxLength) {
        this.maxLength = maxLength;
    }

    public boolean isRestrictive() {
        return  minSpecial > 0 || minNumeric > 0 || minLower > 0 || minUpper > 0
        || minLength > minUpper + minLower + minNumeric + minSpecial;
    }

    @Override
    public boolean equals(Object object) {
        if(!(object instanceof PasswordRestriction)) {
            return false;
        }

        PasswordRestriction other = (PasswordRestriction) object;
        return other.getId().equals(getId()) && other.getName().equals(getName());
    }

    public String toString() {
        List<String> sections = getEnabledSettingsStrings();
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
        description.append(maxLength);
        description.append(" characters in total");

        return description.toString();
    }

    private List<String> getEnabledSettingsStrings() {
        List<String> sections = new ArrayList<>();
        addSectionIfNeeded(sections, minSpecial,
                minSpecial+" non alpha-numeric "+getCharactersPhrase(minSpecial)+
                        " from the set \'"+specialCharacters+"\'");
        addSectionIfNeeded(sections, minNumeric,minNumeric + " numeric " + getCharactersPhrase(minNumeric));
        addSectionIfNeeded(sections, minLower, minLower+" lower case "+getCharactersPhrase(minLower));
        addSectionIfNeeded(sections, minUpper, minUpper+" upper case "+getCharactersPhrase(minUpper));
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
    }
}
