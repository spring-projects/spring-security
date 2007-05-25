package org.acegisecurity.config;

import java.util.Collections;

import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.providers.AuthenticationProvider;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.core.OrderComparator;

public class AuthenticationProviderOrderResolver implements BeanFactoryPostProcessor {
	
	/**
	 * 
	 */
	public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
		// retrieve all the AuthenticationProvider instances
		ManagedList providers = retrieveAllAuthenticationProviders(beanFactory);
		String[] names = beanFactory.getBeanNamesForType(AuthenticationManager.class);
		RootBeanDefinition definition = (RootBeanDefinition)beanFactory.getBeanDefinition(names[0]);
		definition.getPropertyValues().addPropertyValue("providers",providers);
	}
	/**
	 * 
	 * @param beanFactory
	 * @return
	 */
	private ManagedList retrieveAllAuthenticationProviders(ConfigurableListableBeanFactory beanFactory) {
		String[] m = beanFactory.getBeanNamesForType(AuthenticationProvider.class);
		ManagedList l = new ManagedList();
		for(int i=0;i<m.length;i++){
			RootBeanDefinition def = (RootBeanDefinition)beanFactory.getBeanDefinition(m[i]);
			l.add(def);
		}
		Collections.sort(l, new OrderComparator());
		return l;
	}

	
}
