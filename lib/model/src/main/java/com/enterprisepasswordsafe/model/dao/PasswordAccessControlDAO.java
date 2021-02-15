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

package com.enterprisepasswordsafe.model.dao;

import com.alsutton.cryptography.Decrypter;
import com.alsutton.cryptography.Encrypter;
import com.enterprisepasswordsafe.accesscontrol.AbstractAccessControl;
import com.enterprisepasswordsafe.cryptography.ObjectWithSecretKey;
import com.enterprisepasswordsafe.model.ConfigurationOptions;
import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.PasswordPermission;
import com.enterprisepasswordsafe.model.cryptography.DecrypterFactory;
import com.enterprisepasswordsafe.model.cryptography.EncrypterFactory;
import com.enterprisepasswordsafe.model.persisted.AbstractActor;
import com.enterprisepasswordsafe.model.persisted.Group;
import com.enterprisepasswordsafe.model.persisted.Membership;
import com.enterprisepasswordsafe.model.persisted.Password;
import com.enterprisepasswordsafe.model.persisted.PasswordAccessControl;
import com.enterprisepasswordsafe.model.persisted.User;

import javax.persistence.EntityManager;
import javax.persistence.NoResultException;
import javax.persistence.TypedQuery;
import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.util.List;
import java.util.Optional;
import java.util.function.BiFunction;
import java.util.stream.Stream;

public class PasswordAccessControlDAO
        extends JPADAOBase<PasswordAccessControl> {

    public PasswordAccessControlDAO(DAORepository daoRepository, EntityManager entityManager) {
        super(daoRepository, entityManager, PasswordAccessControl.class);
    }

    public PasswordAccessControl getAccessControl(final User user, final Password item)  {
        if (isGroupFirstOrdering()) {
            return getAccessControl(user, item, this::getWriteAccessControlViaGroups, this::getDirectAccessControl);
        }
        return getAccessControl(user, item, this::getDirectAccessControl, this::getWriteAccessControlViaGroups);
    }

    public PasswordAccessControl getReadAccessControl(final User user, final Password item) {
        if (isGroupFirstOrdering()) {
          return getAccessControl(user, item, this::getReadAccessControlViaGroups, this::getDirectAccessControl);
        }
        return getAccessControl(user, item, this::getDirectAccessControl, this::getReadAccessControlViaGroups);
    }

    private PasswordAccessControl getAccessControl(final User user, final Password password,
                                                   BiFunction<User, Password, PasswordAccessControl>... functions) {
        for(BiFunction<User,Password,PasswordAccessControl> function : functions) {
            PasswordAccessControl accessControl = function.apply(user, password);
            if (accessControl != null) {
                return accessControl;
            }
        }
        return null;
    }

    public PasswordAccessControl create(final AbstractActor actor, final Password item,
                                        final PasswordPermission permission, final boolean writeToDB)
            throws GeneralSecurityException {
        if (permission == PasswordPermission.NONE) {
            PasswordAccessControl existingUac = item.getAccessControls().get(actor);
            if (existingUac != null) {
                delete(existingUac);
            }
            return null;
        }

        PrivateKey modifyKey = null;
        if (permission == PasswordPermission.WRITE) {
            modifyKey = item.getModifyKey();
        }

        PasswordAccessControl accessControl =
                new PasswordAccessControl(actor, item, item.getReadKey(), modifyKey);
        if (writeToDB) {
            store(actor, accessControl);
        }
        return accessControl;
    }

    public PasswordAccessControl create(final AbstractActor actor, final Password item,
                                        final PasswordPermission permission)
            throws UnsupportedEncodingException, GeneralSecurityException {
        return create(actor, item, permission, true);
    }

    public PasswordAccessControl getDirectAccessControl(final AbstractActor actor, final Password item) {
        if (actor == null || item == null) {
            return null;
        }

        PasswordAccessControl accessControl = item.getAccessControls().get(actor);
        if(accessControl == null) {
            return null;
        }

        return decrypt(actor, accessControl);
    }

    public List<PasswordAccessControl> getAllAccessControlsViaGroupMemberships(User user) {
        TypedQuery<PasswordAccessControl> query =
                entityManager.createNamedQuery(
                        "GroupAccessControl.getAllAccessControlsForUserViaMemberships",
                        PasswordAccessControl.class);
        query.setParameter("user", user);
        return query.getResultList();
    }


    private PasswordAccessControl getReadAccessControlViaGroups(User user, Password password) {
        return getAccessControlViaGroups(user, getAccessControlsViaGroupMemberships(user, password));
    }

    private PasswordAccessControl getWriteAccessControlViaGroups(User user, Password password) {
        return getAccessControlViaGroups(user, getWriteAccessControlsViaGroupMemberships(user, password));
    }

    private PasswordAccessControl getAccessControlViaGroups(User user, Stream<PasswordAccessControl> candidates) {
        Optional<PasswordAccessControl> passwordAccessControlOptional = candidates.findFirst();

        if(passwordAccessControlOptional.isEmpty()) {
            return null;
        }

        PasswordAccessControl accessControl = passwordAccessControlOptional.get();
        try {
            Membership membership =
                    daoRepository.getMembershipDAO().getMembership(user, (Group) accessControl.getActor());
            decrypt(membership, accessControl);
            return accessControl;
        } catch (GeneralSecurityException e) {
            return null;
        }
    }

    private Stream<PasswordAccessControl> getAccessControlsViaGroupMemberships(User user, Password password) {
        TypedQuery<PasswordAccessControl> query =
                entityManager.createNamedQuery(
                        "GroupAccessControl.getAccessControlForUserViaMemberships",
                        PasswordAccessControl.class);
        query.setParameter("user", user);
        query.setParameter("password", password);
        return query.getResultStream().filter(accessControl -> accessControl.getEncryptedReadKey() != null);
    }

    private Stream<PasswordAccessControl> getWriteAccessControlsViaGroupMemberships(User user, Password password) {
        return getAccessControlsViaGroupMemberships(user,password)
                .filter(accessControl -> accessControl.getEncryptedModifyKey() != null);
    }

    private PasswordAccessControl decrypt(ObjectWithSecretKey keyholder, PasswordAccessControl accessControl) {
        if (keyholder == null || accessControl == null) {
            return null;
        }

        try {
            Decrypter decrypter = new DecrypterFactory(keyholder).decrypterFor(accessControl);
            accessControl.decryptKeys(decrypter);
            return accessControl;
        } catch (GeneralSecurityException | NoResultException e) {
            return null;
        }
    }

    public void updateEncryptionOnKeys(final User user, final EncrypterFactory encrypterFactory,
                                       final List<? extends PasswordAccessControl> accessControls)
            throws GeneralSecurityException {
        if (user == null || encrypterFactory == null || accessControls == null) {
            throw new IllegalArgumentException("All parameters are required.");
        }

        DecrypterFactory decrypterFactory = new DecrypterFactory(user);
        for (PasswordAccessControl accessControl : accessControls) {
            Decrypter decrypter = decrypterFactory.decrypterFor(accessControl);
            accessControl.decryptKeys(decrypter);
        }

        for (AbstractAccessControl accessControl : accessControls) {
            Encrypter encrypter = encrypterFactory.encrypterFor(accessControl);
            accessControl.encryptKeys(encrypter);
            entityManager.persist(accessControl);
        }
    }
    public void store(final AbstractActor actor, final PasswordAccessControl accessControl)
            throws GeneralSecurityException {
        store(accessControl, new EncrypterFactory(actor).encrypterFor(accessControl));
    }

    public void store(final PasswordAccessControl accessControl, final Encrypter encrypter)
            throws GeneralSecurityException {
        accessControl.encryptKeys(encrypter);
        store(accessControl);
    }

    private boolean isGroupFirstOrdering() {
        String precedence =
                daoRepository.getConfigurationDAO().get(ConfigurationOptions.PERMISSION_PRECEDENCE);
        return precedence != null && precedence.equals("G");
    }
}
