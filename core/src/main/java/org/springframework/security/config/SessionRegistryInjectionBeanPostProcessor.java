package org.springframework.security.config;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.ListableBeanFactory;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.security.concurrent.ConcurrentSessionController;
import org.springframework.security.concurrent.ConcurrentSessionControllerImpl;
import org.springframework.security.concurrent.SessionRegistry;
import org.springframework.security.ui.AbstractProcessingFilter;
import org.springframework.security.ui.SessionFixationProtectionFilter;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Registered by the <tt>AuthenticationManagerBeanDefinitionParser</tt> if an external
 * ConcurrentSessionController is set (and hence an external SessionRegistry).
 * Its responsibility is to set the SessionRegistry on namespace-registered beans which require access
 * to it.
 * <p>
 * It will attempt to read the registry directly from the registered controller. If that fails, it will look in
 * the application context for a registered SessionRegistry bean.
 *
 * See SEC-879.
 *
 * @author Luke Taylor
 * @since 2.0.3
 */
class SessionRegistryInjectionBeanPostProcessor implements BeanPostProcessor, BeanFactoryAware {
    private final Log logger = LogFactory.getLog(getClass());
    private ListableBeanFactory beanFactory;
    private SessionRegistry sessionRegistry;
    private final String controllerBeanName;

    SessionRegistryInjectionBeanPostProcessor(String controllerBeanName) {
        this.controllerBeanName = controllerBeanName;
    }

    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        if (BeanIds.FORM_LOGIN_FILTER.equals(beanName) ||
                BeanIds.OPEN_ID_FILTER.equals(beanName)) {
            ((AbstractProcessingFilter) bean).setSessionRegistry(getSessionRegistry());
        } else if (BeanIds.SESSION_FIXATION_PROTECTION_FILTER.equals(beanName)) {
            ((SessionFixationProtectionFilter)bean).setSessionRegistry(getSessionRegistry());
        }

        return bean;
    }

    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }

    private SessionRegistry getSessionRegistry() {
        if (sessionRegistry != null) {
            return sessionRegistry;
        }

        logger.info("Attempting to read SessionRegistry from registered ConcurrentSessionController bean");

        ConcurrentSessionController controller = (ConcurrentSessionController) beanFactory.getBean(controllerBeanName);

        if (controller instanceof ConcurrentSessionControllerImpl) {
            sessionRegistry = ((ConcurrentSessionControllerImpl)controller).getSessionRegistry();

            return sessionRegistry;
        }

        logger.info("ConcurrentSessionController is not a standard implementation. SessionRegistry could not be read from it. Looking for it in the context.");

        List<SessionRegistry> sessionRegs = new ArrayList<SessionRegistry>(beanFactory.getBeansOfType(SessionRegistry.class).values());

        if (sessionRegs.size() == 0) {
            throw new SecurityConfigurationException("concurrent-session-controller-ref was set but no SessionRegistry could be obtained from the application context.");
        }

        if (sessionRegs.size() > 1) {
            logger.warn("More than one SessionRegistry instance in application context. Possible configuration errors may result.");
        }

        sessionRegistry = (SessionRegistry) sessionRegs.get(0);

        return sessionRegistry;
    }

    public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
        this.beanFactory = (ListableBeanFactory) beanFactory;
    }
}
