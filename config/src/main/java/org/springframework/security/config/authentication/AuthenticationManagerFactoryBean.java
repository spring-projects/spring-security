package org.springframework.security.config.authentication;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.BeanIds;

/**
 * Factory bean for the namespace AuthenticationManager, which allows a more meaningful error message
 * to be reported in the <tt>NoSuchBeanDefinitionException</tt>, if the user has forgotten to declare
 * the &lt;authentication-manager&gt; element.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class AuthenticationManagerFactoryBean implements FactoryBean<AuthenticationManager>, BeanFactoryAware {
    private BeanFactory bf;
    public static final String MISSING_BEAN_ERROR_MESSAGE = "Did you forget to add a gobal <authentication-manager> element " +
            "to your configuration (with child <authentication-provider> elements)? Alternatively you can use the " +
            "authentication-manager-ref attribute on your <http> and <global-method-security> elements.";

    public AuthenticationManager getObject() throws Exception {
        try {
             return (AuthenticationManager) bf.getBean(BeanIds.AUTHENTICATION_MANAGER);
        } catch (NoSuchBeanDefinitionException e) {
            if (BeanIds.AUTHENTICATION_MANAGER.equals(e.getBeanName())) {
                throw new NoSuchBeanDefinitionException(BeanIds.AUTHENTICATION_MANAGER, MISSING_BEAN_ERROR_MESSAGE);
            }
            throw e;
        }
    }

    public Class<? extends AuthenticationManager> getObjectType() {
        return ProviderManager.class;
    }

    public boolean isSingleton() {
        return true;
    }

    public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
        bf = beanFactory;
    }

}
