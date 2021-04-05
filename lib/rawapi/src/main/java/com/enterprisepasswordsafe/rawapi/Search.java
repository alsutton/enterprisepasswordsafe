package com.enterprisepasswordsafe.rawapi;

import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.persisted.Location;
import com.enterprisepasswordsafe.model.persisted.Password;
import com.enterprisepasswordsafe.model.persisted.PasswordAccessControl;
import com.enterprisepasswordsafe.model.persisted.User;
import com.enterprisepasswordsafe.model.utils.PasswordDecrypter;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collection;
import java.util.Set;
import java.util.TreeSet;

public class Search {

    private final DAORepository daoRepository;
    private final PasswordDecrypter passwordDecrypter = new PasswordDecrypter();

    public Search(DAORepository daoRepository) {
        this.daoRepository = daoRepository;
    }

    public Set<Long> searchForIds(User user, String searchUsername, Long searchLocation)
            throws IOException, GeneralSecurityException {
        Set<Long> ids = new TreeSet<>();
        if (searchUsername == null) {
            return ids;
        }

        Location location = daoRepository.getLocationDAO().getById(searchLocation);

        searchAccessControls(searchUsername, location,
                user.getUserAccessControls(),
                ids);
        searchAccessControls(searchUsername, location,
                daoRepository.getPasswordAccessControlDAO().getAllAccessControlsViaGroupMemberships(user),
                ids);

        return ids;
    }

    private void searchAccessControls(String searchUsername, Location searchLocation,
                                      Collection<PasswordAccessControl> accessControls, Set<Long> matchingIds)
            throws GeneralSecurityException, IOException {
        for(PasswordAccessControl ac : accessControls) {
            if(!searchLocation.equals(ac.getPassword().getLocation())) {
                continue;
            }
            addIdIfMatches(searchUsername, ac, matchingIds);
        }
    }

    private void addIdIfMatches(String searchUsername, PasswordAccessControl ac, Set<Long> ids)
            throws GeneralSecurityException, IOException {
        if(ac == null) {
            return;
        }
        Password password = ac.getPassword();
        passwordDecrypter.decrypt(password, ac);
        if (searchUsername.equals(password.getDecryptedProperties().getProperty("USERNAME"))) {
            ids.add(password.getId());
        }
    }
}
