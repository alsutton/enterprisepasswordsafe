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

import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.EntityState;
import com.enterprisepasswordsafe.model.PasswordPermission;
import com.enterprisepasswordsafe.model.persisted.AbstractActor;
import com.enterprisepasswordsafe.model.persisted.Group;
import com.enterprisepasswordsafe.model.persisted.Password;
import com.enterprisepasswordsafe.model.persisted.PasswordAccessControl;
import com.enterprisepasswordsafe.model.persisted.User;
import com.enterprisepasswordsafe.model.utils.PasswordEncrypter;

import javax.persistence.EntityManager;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.sql.SQLException;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Stream;

public final class PasswordDAO
        extends JPADAOBase<Password>  {

    protected PasswordDAO(DAORepository daoRepository, EntityManager entityManager) {
        super(daoRepository, entityManager, Password.class);
    }

    public PasswordAccessControl storeNewPassword(final Password password, final User creator )
		throws GeneralSecurityException, IOException {
        Group adminGroup = daoRepository.getGroupDAO().getAdminGroup(creator);
        if (adminGroup == null) {
            throw new GeneralSecurityException("You can not create new passwords.");
        }

        PasswordAccessControlDAO acDAO = daoRepository.getPasswordAccessControlDAO();
        PasswordAccessControl accessControl = acDAO.create(adminGroup, password, PasswordPermission.WRITE);
        acDAO.store(adminGroup, accessControl);

        accessControl = acDAO.create(creator, password, PasswordPermission.WRITE);
        acDAO.store(creator, accessControl);
        return accessControl;
	}

    public void write(final User theCreator, final Group adminGroup, Password password)
            throws SQLException, GeneralSecurityException, IOException {
        PasswordAccessControlDAO acDAO = daoRepository.getPasswordAccessControlDAO();
        PasswordAccessControl newUac = acDAO.create(theCreator, password, PasswordPermission.WRITE);
        write(password, newUac);
        acDAO.store(theCreator, newUac);

        if( adminGroup != null ) {
            PasswordAccessControl adminAc = acDAO.create(adminGroup, password, PasswordPermission.WRITE);
            acDAO.store(adminGroup, adminAc);
        }
    }

    public void write(final Password password, final Group group)
            throws SQLException, GeneralSecurityException, IOException {
        PasswordAccessControlDAO acDAO = daoRepository.getPasswordAccessControlDAO();
    	PasswordAccessControl ac = acDAO.create(group, password, PasswordPermission.WRITE);
    	acDAO.store(group, ac);
        write(password, ac);
    }

    public void write(final Password password, final PasswordAccessControl ac)
        throws SQLException, GeneralSecurityException, IOException {
        PasswordEncrypter encrypter = new PasswordEncrypter();
        encrypter.encrypt(password, ac);
        store(password);
    }

    public final Set<String> getEmailsOfUsersWithAccess(final Password password) {
        Set<String> emailAddresses = new HashSet<>();
        getEmailAddressesWork(password.getAccessControls().keySet().stream(), emailAddresses);
        return emailAddresses;
    }

    private void getEmailAddressesWork(final Stream<AbstractActor> actors,
                                       final Set<String> emailAddresses) {
        actors.filter(actor -> actor.getState() == EntityState.ENABLED)
                .forEach(actor -> {
                    if( actor instanceof User) {
                        emailAddresses.add( ((User)actor).getEmail() );
                    } else if (actor instanceof Group) {
                        getEmailAddressesWork(((Group)actor).getMemberships().keySet().stream(), emailAddresses);
                    }});
    }
}
