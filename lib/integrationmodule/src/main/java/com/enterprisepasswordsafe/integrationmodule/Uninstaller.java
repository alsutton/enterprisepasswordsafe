package com.enterprisepasswordsafe.integrationmodule;

import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.persisted.IntegrationModule;

public class Uninstaller {
    private DAORepository daoRepository;

    public Uninstaller(DAORepository daoRepository) {
        this.daoRepository = daoRepository;
    }

    public void uninstall(final IntegrationModule module)
            throws Exception {
        // First run the uninstall method of the integrator class. This
        // allows the uninstaller to stop the removal if uninstallation
        // will cause a configuration problem.
        Class<?> integratorClass = Class.forName(module.getClassName());
        PasswordChanger changer = (PasswordChanger) integratorClass.getDeclaredConstructor().newInstance();
        changer.uninstall();

        // Delete the details of the node.
        daoRepository.getIntegrationModuleDAO().delete(module);
    }

}
