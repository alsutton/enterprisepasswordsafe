package com.enterprisepasswordsafe.integrationmodule;

import com.enterprisepasswordsafe.model.DAORepository;
import com.enterprisepasswordsafe.model.persisted.IntegrationModule;

import java.lang.reflect.InvocationTargetException;
import java.util.List;

public class PasswordChangerFactory {

    private DAORepository daoRepository;

    public PasswordChangerFactory(DAORepository daoRepository) {
        this.daoRepository = daoRepository;
    }

    public PasswordChanger getPasswordChangerInstance(final IntegrationModule module)
            throws ClassNotFoundException, InstantiationException, IllegalAccessException,
            NoSuchMethodException, InvocationTargetException {
        Class<?> integratorClass = Class.forName(module.getClassName());
        return (PasswordChanger) integratorClass.getDeclaredConstructor().newInstance();
    }

    public List<PasswordChangerProperty> getPasswordChangerProperties(final IntegrationModule module )
            throws ClassNotFoundException, InstantiationException, IllegalAccessException,
            NoSuchMethodException, InvocationTargetException {
        Class<?> integratorClass = Class.forName(module.getClassName());
        PasswordChanger changer = (PasswordChanger) integratorClass.getDeclaredConstructor().newInstance();
        return changer.getProperties();
    }

}
