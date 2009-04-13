package org.springframework.security.config;

import java.util.Map;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.security.web.authentication.AbstractProcessingFilter;
import org.springframework.security.web.authentication.RememberMeServices;
import org.springframework.security.web.authentication.www.BasicProcessingFilter;
import org.springframework.util.Assert;

/**
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 2.0
 */
public class RememberMeServicesInjectionBeanPostProcessor implements BeanPostProcessor, BeanFactoryAware {
    private Log logger = LogFactory.getLog(getClass());

    private ListableBeanFactory beanFactory;

    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        if (bean instanceof AbstractProcessingFilter) {
            AbstractProcessingFilter pf = (AbstractProcessingFilter) bean;

            if (pf.getRememberMeServices() == null) {
                logger.info("Setting RememberMeServices on bean " + beanName);
                pf.setRememberMeServices(getRememberMeServices());
            }
        } else if (BeanIds.BASIC_AUTHENTICATION_FILTER.equals(beanName)) {
            // NB: For remember-me to be sent back, a user must submit a "_spring_security_remember_me" with their login request.
            // Most of the time a user won't present such a parameter with their BASIC authentication request.
            // In the future we might support setting the AbstractRememberMeServices.alwaysRemember = true, but I am reluctant to
            // do so because it seems likely to lead to lower security for 99.99% of users if they set the property to true.

            BasicProcessingFilter bf = (BasicProcessingFilter) bean;
            logger.info("Setting RememberMeServices on bean " + beanName);
            bf.setRememberMeServices(getRememberMeServices());
        }

        return bean;
    }

    private RememberMeServices getRememberMeServices() {
        Map<?,?> beans = beanFactory.getBeansOfType(RememberMeServices.class);

        Assert.isTrue(beans.size() > 0, "No RememberMeServices configured");
        Assert.isTrue(beans.size() == 1, "Use of '<remember-me />' requires a single instance of RememberMeServices " +
                "in the application context, but more than one was found.");

        return (RememberMeServices) beans.values().toArray()[0];
    }

    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }

    public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
        this.beanFactory = (ListableBeanFactory) beanFactory;
    }
}
