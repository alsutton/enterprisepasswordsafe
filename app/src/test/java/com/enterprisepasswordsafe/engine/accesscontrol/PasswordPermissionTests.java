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

import com.enterprisepasswordsafe.accesscontrol.PasswordPermission;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class PasswordPermissionTests {

    @Test
    public void testNullIsSeenAsNone() {
        Assertions.assertEquals(PasswordPermission.NONE, PasswordPermission.fromRepresentation(null));
    }

    @Test
    public void testCharacterMatches() {
        Assertions.assertEquals(PasswordPermission.NONE, PasswordPermission.fromRepresentation('N'));
        Assertions.assertEquals(PasswordPermission.READ, PasswordPermission.fromRepresentation('V'));
        Assertions.assertEquals(PasswordPermission.MODIFY, PasswordPermission.fromRepresentation('M'));
    }

    @Test
    public void testNumericMatches() {
        Assertions.assertEquals(PasswordPermission.NONE, PasswordPermission.fromRepresentation("0"));
        Assertions.assertEquals(PasswordPermission.READ, PasswordPermission.fromRepresentation("1"));
        Assertions.assertEquals(PasswordPermission.MODIFY, PasswordPermission.fromRepresentation("2"));
    }

}
