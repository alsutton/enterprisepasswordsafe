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

import java.security.PrivateKey;
import java.security.PublicKey;

public class UserAccessControl extends AccessControl {

    public UserAccessControl(final String newUserId, final String newItemId,
            final PrivateKey newModifyKey, final PublicKey newReadKey) {
        super(newItemId, newUserId, newModifyKey, newReadKey);
    }

    public String getUserId() {
        return getAccessorId();
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder extends AccessControlBuilder<UserAccessControl> {
        @Override
        public UserAccessControl build() {
            return new UserAccessControl(itemId, accessorId, modifyKey, readKey);
        }
    }
}
