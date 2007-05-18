/**
 * 
 */
package org.acegisecurity.config;

import org.acegisecurity.providers.dao.DaoAuthenticationProvider;
import org.acegisecurity.userdetails.UserDetailsService;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.RootBeanDefinition;

/**
 * @author vpuri
 * 
 */
public class AuthenticationRepositoryDependenciesConfigurer implements BeanFactoryPostProcessor {

	public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
		System.out.println("whyyyy??????");
		String[] userDetailServices = beanFactory.getBeanNamesForType(UserDetailsService.class);

		String[] authenticationProvider = beanFactory.getBeanNamesForType(DaoAuthenticationProvider.class);

		RootBeanDefinition definition = (RootBeanDefinition) beanFactory.getBeanDefinition(authenticationProvider[0]);

		// there should be only one principal-repository defined, pick the first
		// one
		if (userDetailServices.length != 0) {
			definition.getPropertyValues().addPropertyValue("userDetailsService",
					new RuntimeBeanReference(userDetailServices[0]));
		}

	}

}
