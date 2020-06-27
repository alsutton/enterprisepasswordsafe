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

package com.enterprisepasswordsafe.engine.accesscontrol;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class AccessControlTests {

    private final String TEST_DATA = getClass().getName();

    @Test
    public void testNullDataDoesntCauseEncryptToCrash()
            throws GeneralSecurityException, UnsupportedEncodingException {
        KeyPair testKeys = generateTestKeys();
        AccessControl accessControl = new AccessControl(null, null,
                testKeys.getPrivate(), testKeys.getPublic());
        Assertions.assertNull(accessControl.encrypt(null));
    }

    @Test
    public void testNullDataDoesntCauseDecryptToCrash()
            throws GeneralSecurityException, UnsupportedEncodingException {
        KeyPair testKeys = generateTestKeys();
        AccessControl accessControl = new AccessControl(null, null,
                testKeys.getPrivate(), testKeys.getPublic());
        Assertions.assertNull(accessControl.decrypt(null));
    }

    @Test
    public void testEncryptionRoundTrip()
            throws GeneralSecurityException, UnsupportedEncodingException {
        KeyPair testKeys = generateTestKeys();
        AccessControl accessControl = new AccessControl(null, null,
                testKeys.getPrivate(), testKeys.getPublic());
        String roundTrip = accessControl.decrypt(accessControl.encrypt(TEST_DATA));
        Assertions.assertEquals(TEST_DATA, roundTrip);
    }

    @Test
    public void testComparisonMatchesItemIdAndNoKeys() {
        AccessControl accessControl1 = new AccessControl("1", null, null, null);
        AccessControl accessControl2 = new AccessControl("1", null, null, null);
        Assertions.assertTrue(accessControl1.compareTo(accessControl2) == 0);
    }

    @Test
    public void testComparisonFailsMatchWithDifferentItemId() {
        AccessControl accessControl1 = new AccessControl("1", null, null, null);
        AccessControl accessControl2 = new AccessControl("2", null, null, null);
        Assertions.assertTrue(accessControl1.compareTo(accessControl2) != 0);
    }

    @Test
    public void testComparisonFailsMatchWithRHSNoModifyKey()
            throws GeneralSecurityException {
        KeyPair testKeys = generateTestKeys();
        AccessControl accessControl1 = new AccessControl("1", null,
                testKeys.getPrivate(), testKeys.getPublic());
        AccessControl accessControl2 = new AccessControl("1", null,
                null, testKeys.getPublic());
        Assertions.assertTrue(accessControl1.compareTo(accessControl2) != 0);
    }

    @Test
    public void testComparisonFailsMatchWithLHSNoModifyKey()
            throws GeneralSecurityException {
        KeyPair testKeys = generateTestKeys();
        AccessControl accessControl1 = new AccessControl("1", null,
                testKeys.getPrivate(), testKeys.getPublic());
        AccessControl accessControl2 = new AccessControl("1", null,
                null, testKeys.getPublic());
        Assertions.assertTrue(accessControl2.compareTo(accessControl1) != 0);
    }

    @Test
    public void testComparisonMatchesWithDifferentKeys()
            throws GeneralSecurityException {
        KeyPair testKeys1 = generateTestKeys();
        AccessControl accessControl1 = new AccessControl("1", null,
                testKeys1.getPrivate(), testKeys1.getPublic());
        KeyPair testKeys2 = generateTestKeys();
        AccessControl accessControl2 = new AccessControl("1", null,
                testKeys2.getPrivate(), testKeys2.getPublic());
        Assertions.assertTrue(accessControl1.compareTo(accessControl2) == 0);
    }

    private KeyPair generateTestKeys()
            throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        return kpg.generateKeyPair();
    }
}
