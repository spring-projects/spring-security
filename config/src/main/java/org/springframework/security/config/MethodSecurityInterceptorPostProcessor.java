package org.springframework.security.config;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.security.AfterInvocationManager;
import org.springframework.security.intercept.method.aopalliance.MethodSecurityInterceptor;

/**
 * BeanPostProcessor which sets the AfterInvocationManager on the global MethodSecurityInterceptor,
 * if one has been configured.
 *
 * @author Luke Taylor
 * @version $Id$
 *
 */
public class MethodSecurityInterceptorPostProcessor implements BeanPostProcessor, BeanFactoryAware{
    private Log logger = LogFactory.getLog(getClass());

    private BeanFactory beanFactory;

    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        if(!GlobalMethodSecurityBeanDefinitionParser.SECURITY_INTERCEPTOR_ID.equals(beanName)) {
            return bean;
        }

        MethodSecurityInterceptor interceptor = (MethodSecurityInterceptor) bean;

        if (beanFactory.containsBean(BeanIds.AFTER_INVOCATION_MANAGER)) {
            logger.debug("Setting AfterInvocationManaer on MethodSecurityInterceptor");
            interceptor.setAfterInvocationManager((AfterInvocationManager)
                    beanFactory.getBean(BeanIds.AFTER_INVOCATION_MANAGER));
        }

        return bean;
    }

    public Object postProcessAfterInitialization(Object bean, String beanName) {
        return bean;
    }

    public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
        this.beanFactory = beanFactory;
    }
}
