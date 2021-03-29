package com.enterprisepasswordsafe.importers;

import com.alsutton.cryptography.Decrypter;
import com.enterprisepasswordsafe.cryptography.DecrypterFactory;
import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.dao.GroupDAO;
import com.enterprisepasswordsafe.model.dao.MembershipDAO;
import com.enterprisepasswordsafe.model.dao.UserDAO;
import com.enterprisepasswordsafe.model.persisted.Group;
import com.enterprisepasswordsafe.model.persisted.User;
import org.apache.commons.csv.CSVRecord;

import java.io.UnsupportedEncodingException;
import java.security.GeneralSecurityException;
import java.util.Iterator;

public class GroupImporter {
    private GroupDAO groupDAO;
    private UserDAO userDAO;
    private MembershipDAO membershipDAO;

    public GroupImporter(DAORepository daoRepository) {
        groupDAO = daoRepository.getGroupDAO();
        userDAO = daoRepository.getUserDAO();
        membershipDAO = daoRepository.getMembershipDAO();
    }

    public void importGroup(final User theImporter, final CSVRecord record)
            throws GeneralSecurityException, UnsupportedEncodingException {
        Iterator<String> valueIterator = record.iterator();
        if (!valueIterator.hasNext()) {
            throw new GeneralSecurityException("No groupname specified.");
        }

        String groupName = valueIterator.next().trim();
        Group theGroup = groupDAO.create(theImporter, groupName);

        Group adminGroup = groupDAO.getAdminGroup(theImporter);
        DecrypterFactory decrypterFactory = new DecrypterFactory(adminGroup);
        while(valueIterator.hasNext()) {
            String memberName = valueIterator.next();
            User thisUser = userDAO.getByName(memberName);
            if (thisUser == null) {
                throw new GeneralSecurityException(memberName + " does not exist");
            }
            Decrypter decrypter = decrypterFactory.decrypterFor(thisUser);
            thisUser.decryptKey(thisUser::getEncryptedAdminAccessKey, decrypter);
            membershipDAO.create(thisUser, theGroup);
        }
    }
}