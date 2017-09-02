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


/**
 * Utility class holding a byte to Hex string converter.
 */
public final class HexConverter {

    /**
     * The array of valid characters in a hex string.
     */
    private static final char[] HEX_BYTES = {'0', '1', '2', '3', '4', '5', '6',
            '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };

    /**
     * The mask to use to extract the top nibble of a byte.
     */

    private static final int TOP_NIBBLE_MASK = 0xf0;

    /**
     * The mask to use to extract the bottom nibble of a byte.
     */

    private static final int BOTTOM_NIBBLE_MASK = 0x0f;

    /**
     * The number of positions to shift a nibble so that it overwrites the
     * other nibble in a byte.
     */

    private static final int NIBBLE_OVERWRITE_SHIFT_SIZE = 4;

    /**
     * Private constructor to avoid instanciation.
     */

    private HexConverter() { }

    /**
     * Convert a byte array into a hex string.
     *
     * @param data
     *            The byte array.
     *
     * @return The hex string equivalent.
     */
    public static String fromBytes(final byte[] data) {
        StringBuffer hexBuffer = new StringBuffer();
        for (int i = 0; i < data.length; i++) {
            byte thisByte = data[i];
            hexBuffer.append(HEX_BYTES[(thisByte & TOP_NIBBLE_MASK) >> NIBBLE_OVERWRITE_SHIFT_SIZE]);
            hexBuffer.append(HEX_BYTES[thisByte & BOTTOM_NIBBLE_MASK]);
        }

        return hexBuffer.toString();
    }

    /**
     * Converts a hex string into a byte array.
     *
     * @param data
     *            The hex string.
     *
     * @return The byte array containg the equivalent data.
     */
    public static byte[] toBytes(final String data) {
        return toBytes(data, 0, null);
    }

    /**
     * Converts a hex string into a byte array.
     *
     * @param data
     *            The hex string.
     * @param startCharacter
     *            The character in the string to start decoding at.
     *
     * @return The byte array containg the equivalent data.
     */
    public static byte[] toBytes(final String data, final int startCharacter) {
        return toBytes(data, startCharacter, null);
    }

    /**
     * Converts a hex string into a byte array.
     *
     * @param data
     *            The hex string.
     * @param startCharacter
     *            The character in the string to start decoding at.
     * @param destination
     *            The byte array to decode to.
     *
     * @return The byte array containg the equivalent data.
     */
    public static byte[] toBytes(final String data, final int startCharacter,
            final byte[] destination) {
        int byteLength = (data.length() - startCharacter) / 2;

        byte[] decodeDestination = destination;
        if (decodeDestination == null) {
            decodeDestination = new byte[byteLength];
        }

        if (decodeDestination.length < byteLength) {
            throw new RuntimeException("Attempt to decode data to a buffer which is too small");
        }

        char[] dataChars = data.toLowerCase().toCharArray();

        for (int i = startCharacter, j = 0; j < byteLength; i += 2, j++) {
            if (dataChars[i] >= '0' && dataChars[i] <= '9') {
            	decodeDestination[j] = (byte) (dataChars[i] - '0');
            } else {
            	decodeDestination[j] = (byte) (dataChars[i] - 'a' + 10);
            }

            decodeDestination[j] <<= NIBBLE_OVERWRITE_SHIFT_SIZE;

            if (dataChars[i+1] >= '0' && dataChars[i+1] <= '9') {
            	decodeDestination[j] |= (byte) (dataChars[i+1] - '0');
            } else {
            	decodeDestination[j] |= (byte) (dataChars[i+1] - 'a' + 10);
            }
        }
        return decodeDestination;
    }

}
