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
import com.enterprisepasswordsafe.proguard.ExternalInterface;
import com.enterprisepasswordsafe.proguard.JavaBean;

/**
 * Object handling the storage of the details of an integration module.
 */
public class PasswordRestriction
        implements Serializable, ExternalInterface {

    /**
     *
     */
    private static final long serialVersionUID = 8341255573165332858L;

    /**
     * The text returned when there are no limitations on passwords.
     */

    private static final String NO_LIMITS_STRING = "There are no restrictions on the contents of the password.";

    /**
     * The characters from which a numeric character can be chosen.
     */

    public static final String NUMERIC_PASSWORD_CHARS = "1234567890";

    /**
     * The characters from which a lower case character can be chosen.
     */

    public static final String LOWER_PASSWORD_CHARS = "abcdefghijklmnopqrstuvwxyz";

    /**
     * The characters from which an upper case character can be chosen.
     */

    public static final String UPPER_PASSWORD_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

    /**
     * The ID used to identify the log password restriction
     */

    public static final String MIGRATED_RESTRICTION_ID = "-2";

    /**
     * The ID used to identify the log password restriction
     */

    public static final String LOGIN_PASSWORD_RESTRICTION_ID = "-1";

    /**
     * The id of this restriction
     */

    private String restrictionId;

    /**
     * The name of this restriction.
     */

    private String name;

    /**
     * Minimum number of numeric characters.
     */

    private int minNumeric;

    /**
     * The minimum number of lower case characters.
     */

    private int minLower;

    /**
     * The minimum number of upper case characters.
     */

    private int minUpper;

    /**
     * The minimum number of "special" characters.
     */

    private int minSpecial;

    /**
     * The minimum length.
     */

    private int minLength;

    /**
     * The maximum length for a password.
     */

    private int maxLength;

    /**
     * The special characters
     */

    private String specialCharacters;

    /**
     * The number of days the password will last for by default.
     */

    private int lifetime;

    /**
     * Creates a new PasswordRestriction instance from the data supplied.
     *
     * @param theName       The name of this restriction.
     * @param theMinLower   The minimum number of lower case characters.
     * @param theMinUpper   The minimum number of upper case characters.
     * @param theMinNumeric The minimum number of numeric characters.
     * @param theMinSpecial The minimum number of special characters.
     * @param theMinLength  The minimum length for the password.
     * @param theSpecial    The set of special characters.
     */

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

    /**
     * Extracts the information about a PasswordRestriction from the JDBC ResultSet.
     *
     * @param rs The result set to extract the data from.
     * @throws SQLException Thrown if there is a problem extracting the information.
     */

    public PasswordRestriction(final ResultSet rs)
            throws SQLException {
        int idx = 1;
        restrictionId = rs.getString(idx++);
        name = rs.getString(idx++);
        minNumeric = rs.getInt(idx++);
        minLower = rs.getInt(idx++);
        minUpper = rs.getInt(idx++);
        minSpecial = rs.getInt(idx++);
        minLength = rs.getInt(idx++);
        specialCharacters = rs.getString(idx++);
        lifetime = rs.getInt(idx++);
        if (rs.wasNull()) {
            lifetime = 0;
        }
        maxLength = rs.getInt(idx);
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
        int special = 0, numeric = 0, upper = 0, lower = 0;

        int passwordLength = password.length();
        if (passwordLength < minLength || passwordLength > maxLength) {
            return false;
        }

        for (int i = 0; i < passwordLength; i++) {
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

    /**
     * Get the lifetime for this restriction.
     *
     * @return The lifetime.
     */

    public int getLifetime() {
        return lifetime;
    }

    /**
     * Set the lifetime of this restriction.
     *
     * @param newLifetime The lifetime to set.
     */

    public void setLifetime(int newLifetime) {
        lifetime = newLifetime;
    }

    /**
     * Set the ID of this restriction. This should only be used in
     * limited cases.
     *
     * @param newId The new ID.
     */

    public void setId(String newId) {
        restrictionId = newId;
    }

    /**
     * Get the Id of this restriction.
     *
     * @return The id of this restriction.
     */
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

    /**
     * Test to see if this restriction actually imposes anything.
     */

    public boolean isRestrictive() {
        return  minSpecial > 0
        ||      minNumeric > 0
        ||      minLower > 0
        ||      minUpper > 0
        ||      minLength > minUpper + minLower + minNumeric + minSpecial;
    }

    @Override
    public boolean equals(Object object) {
        if(!(object instanceof PasswordRestriction)) {
            return false;
        }

        PasswordRestriction other = (PasswordRestriction) object;
        return other.getId().equals(getId())
            && other.getName().equals(getName());
    }

    /**
     * Creates a textual string for the password restrictions.
     *
     * @return A textual description of the descriptions.
     */

    public String toString() {
        List<String> sections = new ArrayList<String>();
        if (minSpecial > 0) {
            sections.add(minSpecial+" non alpha-numeric "+getCharactersPhrase(minSpecial)+
                    " from the set \'"+specialCharacters+"\'");
        }
        if (minNumeric > 0) {
            sections.add(minNumeric + " numeric " + getCharactersPhrase(minNumeric));
        }
        if (minLower > 0) {
            sections.add(minLower+" lower case "+getCharactersPhrase(minLower));
        }
        if (minUpper > 0) {
            sections.add(minUpper+" upper case "+getCharactersPhrase(minUpper));
        }
        if (minLength > minUpper + minLower + minNumeric + minSpecial) {
            sections.add(minLength+" "+getCharactersPhrase(minLength)+" in total");
        }

        int sectionCount = sections.size();
        if (sectionCount == 0) {
            return NO_LIMITS_STRING;
        }

        StringBuilder description = new StringBuilder();
        if (sectionCount > 0) {
            description.append("The password must have");
            if (sectionCount > 0) {
                description.append(" at least ");
                for (int i = 0; i < sectionCount - 1; i++) {
                    description.append(sections.get(i));
                    description.append(", ");
                }

                if (sectionCount > 1) {
                    description.append("and ");
                }
                description.append(sections.get(sectionCount - 1));
            }

            if (sectionCount > 1) {
                description.append(", and");
            }
            description.append(" at most ");
            description.append(maxLength);
            description.append(" characters in total");

            return description.toString();
        }

        return "There are no restrictions on the password";
    }

    /**
     * Returns character or characters depending on the count.
     *
     * @param count The number of characters to get the phrase for.
     * @return The string "character" or "characters".
     */

    private String getCharactersPhrase(int count) {
        if (count == 1) {
            return "character";
        }

        return "characters";
    }

    /**
     * Summary object for a PasswordRestriction
     */

    public static class Summary implements JavaBean {
        /**
         * The ID of the restriction
         */

        private String id;

        /**
         * The name of the module this is a summary for.
         */

        private String name;

        /**
         * Constructors. Stores information.
         */

        public Summary(String newId, String newName) {
            id = newId;
            name = newName;
        }

        /**
         * Get the ID from this summary.
         *
         * @return The Id for the restriction represented by this summary.
         */

        public String getId() {
            return id;
        }

        /**
         * Get the namefrom this summary.
         *
         * @return The name for the restriction represented by this summary.
         */

        public String getName() {
            return name;
        }

    }
}
