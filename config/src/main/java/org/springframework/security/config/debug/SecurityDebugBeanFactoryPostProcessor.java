package org.springframework.security.config.debug;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.security.config.BeanIds;
import org.springframework.security.web.FilterChainProxy;

/**
 * @author Luke Taylor
 */
public class SecurityDebugBeanFactoryPostProcessor implements BeanFactoryPostProcessor {

    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
        Logger.logger.warn("\n\n" +
                "********************************************************************\n" +
                "**********        Security debugging is enabled.       *************\n" +
                "**********    This may include sensitive information.  *************\n" +
                "**********      Do not use in a production system!     *************\n" +
                "********************************************************************\n\n");
        if (beanFactory.getBean(BeanIds.SPRING_SECURITY_FILTER_CHAIN) != null) {
            FilterChainProxy fcp = beanFactory.getBean(BeanIds.FILTER_CHAIN_PROXY, FilterChainProxy.class);
            beanFactory.registerSingleton(BeanIds.DEBUG_FILTER, new DebugFilter(fcp));
            // Overwrite the filter chain alias
            beanFactory.registerAlias(BeanIds.DEBUG_FILTER, BeanIds.SPRING_SECURITY_FILTER_CHAIN);
        }
    }
}
