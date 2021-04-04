package com.enterprisepasswordsafe.integrationmodule;

import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.persisted.IntegrationModule;

public class Installer {

    private DAORepository daoRepository;

    public Installer(DAORepository daoRepository) {
        this.daoRepository = daoRepository;
    }

    public void install(final IntegrationModule module)
            throws Exception {
        // First run the install method of the integrator class. This
        // allows the installer to stop the installation if it will
        // a configuration problem.
        Class<?> integratorClass = Class.forName(module.getClassName());

        PasswordChanger changer = (PasswordChanger) integratorClass.getDeclaredConstructor().newInstance();
        changer.install();

        daoRepository.getIntegrationModuleDAO().store(module);
    }
}

