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
import java.security.*;

public class GroupAccessControlTests {

    @Test
    public void testBuilder()
            throws GeneralSecurityException, UnsupportedEncodingException {
        KeyPair testKeys = generateTestKeys();
        GroupAccessControl testGac = GroupAccessControl.builder()
                .withAccessorId("Accessor")
                .withItemId("Item")
                .withModifyKey(testKeys.getPrivate())
                .withReadKey(testKeys.getPublic())
                .build();

        Assertions.assertEquals("Accessor", testGac.getGroupId());
        Assertions.assertEquals("Item", testGac.getItemId());
        Assertions.assertEquals(testKeys.getPrivate(), testGac.getModifyKey());
        Assertions.assertEquals(testKeys.getPublic(), testGac.getReadKey());
    }

    @Test
    public void testBuilderCopyFrom()
            throws GeneralSecurityException, UnsupportedEncodingException {
        KeyPair testKeys = generateTestKeys();
        GroupAccessControl firstGac = GroupAccessControl.builder()
                .withAccessorId("Accessor")
                .withItemId("Item")
                .withModifyKey(testKeys.getPrivate())
                .withReadKey(testKeys.getPublic())
                .build();
        GroupAccessControl testGac = GroupAccessControl.builder().copyFrom(firstGac).build();

        Assertions.assertEquals("Accessor", testGac.getGroupId());
        Assertions.assertEquals("Item", testGac.getItemId());
        Assertions.assertEquals(testKeys.getPrivate(), testGac.getModifyKey());
        Assertions.assertEquals(testKeys.getPublic(), testGac.getReadKey());
    }

    private KeyPair generateTestKeys()
            throws NoSuchAlgorithmException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        return kpg.generateKeyPair();
    }
}
