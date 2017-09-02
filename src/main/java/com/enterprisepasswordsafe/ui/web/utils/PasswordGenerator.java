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

package com.enterprisepasswordsafe.ui.web.utils;

import java.util.Random;

import javax.servlet.http.HttpServletRequest;

import com.enterprisepasswordsafe.engine.database.PasswordRestriction;

/**
 * Utility class to assist in password generation.
 */
public final class PasswordGenerator implements com.enterprisepasswordsafe.engine.utils.PasswordGenerator {

	/**
	 * Empty string used for password generation
	 */

	private static final String EMPTY_STRING = "";

    /**
     * The default minimum password length.
     */

    private static final int ABSOLUTE_MINIMUM_LENGTH = 8;

    /**
     * The maximum length of characters to add on the end of any requirement.
     */

    private static final int MAXIMUM_EXTENSION_SIZE = 16;

    /**
     * The random number generator.
     */

    private static final Random RANDOM_NUMBER_GENERATOR = new Random();

    /**
     * Private constructor, to avoid instanciation.
     */

    private PasswordGenerator() { }

    /**
     * Generates a new password.
     *
     * @param request The Servlet request.
     * @param startSpecial Whether or not the password must start with a special character.
     *
     * @return A generated password.
     */
    public String generate(final HttpServletRequest request, boolean startSpecial) {
        int upperCount = extractValue(request, "upper", 1);
        int lowerCount = extractValue(request, "lower", 1);
        int numericCount = extractValue(request, "numeric", 1);
        int specialCount = extractValue(request, "special", 1);
        String chars = request.getParameter("chars");
        if( chars == null ) {
        	chars = EMPTY_STRING;
        }

        // Work out the password length
        int minLength;
        try {
        	minLength = Integer.parseInt(request.getParameter("min"));
        } catch (NumberFormatException nfe) {
        	minLength = ABSOLUTE_MINIMUM_LENGTH;
        }

        int maxLength;
        try {
        	maxLength = Integer.parseInt(request.getParameter("max"));
        } catch (NumberFormatException nfe) {
        	maxLength = minLength + RANDOM_NUMBER_GENERATOR.nextInt(MAXIMUM_EXTENSION_SIZE);
        }

        return generate(upperCount, lowerCount, numericCount, specialCount, minLength, maxLength, chars, startSpecial);
    }

    /**
     * Generate a password from a password restriction
     *
     * @param restriction The restriction to generate the password from.
     *
     * @return The generated password.
     */

    public String generate(PasswordRestriction restriction) {
        return generate(restriction, false);
    }

    /**
     * Generate a password from a password restriction
     *
     * @param restriction The restriction to generate the password from.
     * @param startSpecial Whether or not the password must start with a special character.
     *
     * @return The generated password.
     */

    public String generate(PasswordRestriction restriction, final boolean startSpecial) {
    	int upper = 0,
    		lower = 0,
    		numeric = 0,
    		special = 0,
    		minLength = 0,
    		maxLength = 0;
    	String specialChars = "";

    	if(restriction != null) {
			upper = restriction.getMinUpper();
			lower = restriction.getMinLower();
			numeric = restriction.getMinNumeric();
			special = restriction.getMinSpecial();
			minLength = restriction.getMinLength();
			maxLength = restriction.getMaxLength();
			specialChars = restriction.getSpecialCharacters();

    	}
    	return generate( upper, lower, numeric, special, minLength, maxLength, specialChars, startSpecial );
    }

    /**
     * Generate a random password with a default set of characteristics.
     *
     * @return The generated password.
     */

    public String generate() {
        return generate( 0, 0, 0, 0, 8, 16, "", false);
    }

    /**
     * Generate a random password with a default set of characteristics.
     *
     * @param startSpecial true if the password should start with one of the special characters, false if not.
     *
     * @return The generated password.
     */

    public String generate(boolean startSpecial) {
    	return generate( 0, 0, 0, 0, 8, 16, "", startSpecial);
    }

    /**
     * Generate a password.
     *
     * @param upperCount The minimum number of upper case characters.
     * @param lowerCount The minimum number of lower case characters.
     * @param numericCount The minimum number of numeric characters.
     * @param specialCount The minimum number of special characters.
     * @param minLength The minimum length for the password.
     * @param maxLength The maximum length for the password.
     * @param specialChars The special characters to use in the password.
     * @param startSpecial true if the password should start with one of the special characters, false if not.
     *
     * @return The generated password.
     */
    public String generate( final int upperCount, final int lowerCount,
    		final int numericCount, int specialCount, int minLength,
    		int maxLength, final String specialChars, boolean startSpecial ) {
    	if(	specialChars.length() > 0
    	&&  specialCount > 0
    	&&  startSpecial) {
    		specialCount -= 1;
    		minLength -= 1;
    		maxLength -= 1;
    	}

    	int trueMinLength = Math.max(minLength, upperCount+lowerCount+numericCount+specialCount);
    	int length;
    	if( trueMinLength == maxLength ) {
    		length = trueMinLength;
    	} else {
	    	synchronized(RANDOM_NUMBER_GENERATOR) {
	        	length = trueMinLength + RANDOM_NUMBER_GENERATOR.nextInt(maxLength-trueMinLength);
	        	if( length > maxLength ) {
	        		length = maxLength;
	        	}
	    	}
    	}


        // Construct the password character set
        StringBuffer passwordCharacters = new StringBuffer(length);
        addCharsToBuffer(passwordCharacters, upperCount, PasswordRestriction.UPPER_PASSWORD_CHARS);
        addCharsToBuffer(passwordCharacters, lowerCount, PasswordRestriction.LOWER_PASSWORD_CHARS);
        addCharsToBuffer(passwordCharacters, numericCount, PasswordRestriction.NUMERIC_PASSWORD_CHARS);
        if( specialChars != null && specialChars.length() > 0 ) {
        	addCharsToBuffer(passwordCharacters, specialCount, specialChars);
        }
        length -= (upperCount + lowerCount + numericCount + specialCount);

        String allChars =   PasswordRestriction.UPPER_PASSWORD_CHARS +
                            PasswordRestriction.LOWER_PASSWORD_CHARS +
                            PasswordRestriction.NUMERIC_PASSWORD_CHARS +
                            specialChars;

        addCharsToBuffer(passwordCharacters, length, allChars);

        // Now randomise the order
        StringBuilder passwordBuffer = new StringBuilder(passwordCharacters.length());

        if( specialChars != null
        &&  !specialChars.isEmpty()
        &&  specialCount > 0
        &&  startSpecial) {
	        // Always start with special. Solaris 10 likes this
	        // and it's generally a good idea
	        passwordBuffer.append(
	        		specialChars.charAt(
	        				RANDOM_NUMBER_GENERATOR.nextInt(
	        						specialChars.length()
							)
					)
				);
        }

        while (passwordCharacters.length() > 0) {
            int nextCharPosition = RANDOM_NUMBER_GENERATOR
                    .nextInt(passwordCharacters.length());
            passwordBuffer.append(passwordCharacters.charAt(nextCharPosition));
            passwordCharacters.deleteCharAt(nextCharPosition);
        }

        // Return the final password.
        return passwordBuffer.toString();
    }

    /**
     * Extracts a value from the servlet request.
     *
     * @param request
     *            The servlet request to extract the value from.
     * @param parameterName
     *            The name of the parameter to extract the value from.
     * @param defaultValue
     *            The default value if none can be extracted.
     *
     * @return The numeric value of a parameter.
     */

    private int extractValue(final HttpServletRequest request,
            final String parameterName, final int defaultValue) {
        try {
            return Integer.parseInt(request.getParameter(parameterName));
        } catch (NumberFormatException nfe) {
            return defaultValue;
        }
    }

    /**
     * Adds a given number of characters from a set to the specified buffer.
     *
     * @param buffer The buffer to add the characters to.
     * @param count The number of characters to add
     * @param characters The characters to choose from.
     */
    private void addCharsToBuffer(final StringBuffer buffer,
            final int count, final String characters) {
    	int charCount = characters.length();
        for (int i = 0; i < count; i++) {
            buffer.append(characters.charAt(RANDOM_NUMBER_GENERATOR.nextInt(charCount)));
        }
    }

    /**
     * The characters available for use in a login password.
     */

    private static final char[] PASSWORD_CHARS = {'1', '2', '3', '4', '5',
            '6', '7', '8', '9', '0', 'b', 'c', 'd', 'f', 'g', 'h', 'j', 'k',
            'l', 'm', 'n', 'p', 'q', 'r', 's', 't', 'v', 'w', 'x', 'z', 'B',
            'C', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R',
            'S', 'T', 'V', 'W', 'X', 'Y', 'Z' };

    /**
     * Generate a random 8 character password. Primarily used when creating new
     * application users.
     *
     * @return The eight character password.
     */

    public String getRandomPassword() {
        StringBuilder passwordBuffer = new StringBuilder(ABSOLUTE_MINIMUM_LENGTH);

        for (int i = 0; i < ABSOLUTE_MINIMUM_LENGTH; i++) {
            passwordBuffer.append(PASSWORD_CHARS[RANDOM_NUMBER_GENERATOR
                    .nextInt(PASSWORD_CHARS.length)]);
        }

        return passwordBuffer.toString();
    }

    //------ Singleton ------

    private static final class InstanceHolder {
        static final PasswordGenerator INSTANCE = new PasswordGenerator();
    }

    public static PasswordGenerator getInstance() {
        return InstanceHolder.INSTANCE;
    }
}
