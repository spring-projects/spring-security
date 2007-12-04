package org.springframework.security.config;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.BeanDefinitionRegistry;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.core.Ordered;
import org.springframework.security.intercept.method.aopalliance.MethodSecurityInterceptor;

/**
 * Provides convenience methods supporting method security configuration.
 * 
 * @author Ben Alex
 * @author Luke Taylor
 *
 */
abstract class MethodSecurityInterceptorUtils {

	private static class MethodSecurityConfigPostProcessor implements BeanFactoryPostProcessor, Ordered {
	
	    public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
	        String[] interceptors = beanFactory.getBeanNamesForType(MethodSecurityInterceptor.class);
	
	        for (int i=0; i < interceptors.length; i++) {
	            BeanDefinition interceptor = beanFactory.getBeanDefinition(interceptors[i]);
	            ConfigUtils.configureSecurityInterceptor(beanFactory, interceptor);
	        }
	    }
	
	    public int getOrder() {
	        return HIGHEST_PRECEDENCE;
	    }
	
	}

	/**
	 * Causes a BeanFactoryPostProcessor to be registered that will ensure all MethodSecurityInterceptor
	 * instances are properly configured with an AccessDecisionManager etc.
	 * 
	 * @param registry to register the BeanPostProcessorWith
	 */
	public static void registerPostProcessorIfNecessary(BeanDefinitionRegistry registry) {
	    if (registry.containsBeanDefinition(BeanIds.INTERCEPT_METHODS_BEAN_FACTORY_POST_PROCESSOR)) {
	        return;
	    }
	
	    registry.registerBeanDefinition(BeanIds.INTERCEPT_METHODS_BEAN_FACTORY_POST_PROCESSOR,
	            new RootBeanDefinition(MethodSecurityInterceptorUtils.MethodSecurityConfigPostProcessor.class));
	}

}
