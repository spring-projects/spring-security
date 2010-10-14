package org.springframework.security.config;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.BeanFactory;
import org.springframework.beans.factory.BeanFactoryAware;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.security.config.BeanIds;
import org.springframework.security.util.FilterChainProxy;
import org.springframework.security.firewall.HttpFirewall;

/**
 * @author Luke Taylor
 */
public class HttpFirewallInjectionBeanPostProcessor implements BeanPostProcessor, BeanFactoryAware {
    private ConfigurableListableBeanFactory beanFactory;
    private String ref;

    public HttpFirewallInjectionBeanPostProcessor(String ref) {
        this.ref = ref;
    }

    public Object postProcessBeforeInitialization(Object bean, String beanName) throws BeansException {
        if (BeanIds.FILTER_CHAIN_PROXY.equals(beanName)) {
            HttpFirewall fw = (HttpFirewall) beanFactory.getBean(ref);
            ((FilterChainProxy)bean).setFirewall(fw);
        }

        return bean;
    }

    public Object postProcessAfterInitialization(Object bean, String beanName) throws BeansException {
        return bean;
    }


    public void setBeanFactory(BeanFactory beanFactory) throws BeansException {
        this.beanFactory = (ConfigurableListableBeanFactory) beanFactory;
    }
}
