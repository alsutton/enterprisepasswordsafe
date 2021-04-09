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

import com.enterprisepasswordsafe.database.Group;

import java.security.PrivateKey;
import java.security.PublicKey;

/**
 * Object modeling a group access control.
 */

public final class GroupAccessControl extends AccessControl {
    private final Group group;

    public GroupAccessControl(final String newGroupId, final String newItemId,
            final PrivateKey newModifyKey, final PublicKey newReadKey) {
        super(newItemId, newGroupId, newModifyKey, newReadKey);
        group = null;
    }

    public String getGroupId() {
        return getAccessorId();
    }

    public Group getGroup() {
        return group;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static class Builder extends AccessControlBuilder<GroupAccessControl> {
        @Override
        public GroupAccessControl build() {
            return new GroupAccessControl(accessorId, itemId, modifyKey, readKey);
        }
    }
}
