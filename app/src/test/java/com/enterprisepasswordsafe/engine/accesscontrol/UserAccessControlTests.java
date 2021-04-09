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

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class UserAccessControlTests {

    @Test
    public void testBuilder()
            throws GeneralSecurityException {
        KeyPair testKeys = generateTestKeys();
        UserAccessControl testUac = UserAccessControl.builder()
                .withAccessorId("Accessor")
                .withItemId("Item")
                .withModifyKey(testKeys.getPrivate())
                .withReadKey(testKeys.getPublic())
                .build();

        Assertions.assertEquals("Accessor", testUac.getUserId());
        Assertions.assertEquals("Item", testUac.getItemId());
        Assertions.assertEquals(testKeys.getPrivate(), testUac.getModifyKey());
        Assertions.assertEquals(testKeys.getPublic(), testUac.getReadKey());
    }

    @Test
    public void testBuilderCopyFrom()
            throws GeneralSecurityException {
        KeyPair testKeys = generateTestKeys();
        UserAccessControl firstUac = UserAccessControl.builder()
                .withAccessorId("Accessor")
                .withItemId("Item")
                .withModifyKey(testKeys.getPrivate())
                .withReadKey(testKeys.getPublic())
                .build();
        UserAccessControl testUac = UserAccessControl.builder().copyFrom(firstUac).build();

        Assertions.assertEquals("Accessor", testUac.getUserId());
        Assertions.assertEquals("Item", testUac.getItemId());
        Assertions.assertEquals(testKeys.getPrivate(), testUac.getModifyKey());
        Assertions.assertEquals(testKeys.getPublic(), testUac.getReadKey());
    }

    private KeyPair generateTestKeys()
            throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        return kpg.generateKeyPair();
    }
}
