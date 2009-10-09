package org.springframework.security.config.authentication;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
 * @version $Id$
 * @since 3.0
 */
public class AuthenticationManagerFactoryBean implements FactoryBean<AuthenticationManager>, BeanFactoryAware {
    private final Log logger = LogFactory.getLog(getClass());
    private BeanFactory bf;

    public AuthenticationManager getObject() throws Exception {
        try {
             return (AuthenticationManager) bf.getBean(BeanIds.AUTHENTICATION_MANAGER);
        } catch (NoSuchBeanDefinitionException e) {
            logger.error(BeanIds.AUTHENTICATION_MANAGER + " bean was not found in the application context.");
            throw new NoSuchBeanDefinitionException("The namespace AuthenticationManager was not found. " +
                    "Did you forget to add an <authentication-manager> element to your configuration with " +
                    "child <authentication-provider> elements ?");
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
