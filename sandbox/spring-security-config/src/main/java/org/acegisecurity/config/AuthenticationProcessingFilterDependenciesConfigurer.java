/**
 * 
 */
package org.acegisecurity.config;

import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.ui.rememberme.RememberMeServices;
import org.acegisecurity.ui.webapp.AuthenticationProcessingFilter;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.RootBeanDefinition;

/**
 * @author vpuri
 * 
 */
public class AuthenticationProcessingFilterDependenciesConfigurer implements BeanFactoryPostProcessor {

	// ~ Methods
	// ================================================================================================
	public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {

		String[] authenticationProcessingFilter = beanFactory.getBeanNamesForType(AuthenticationProcessingFilter.class);

		RootBeanDefinition def = (RootBeanDefinition) beanFactory.getBeanDefinition(authenticationProcessingFilter[0]);

		String[] remServiceNames = beanFactory.getBeanNamesForType(RememberMeServices.class);

		if (remServiceNames.length > 0) {
			def.getPropertyValues().addPropertyValue("rememberMeServices",
					(RootBeanDefinition) beanFactory.getBeanDefinition(remServiceNames[0]));
		}

		String[] authManager = beanFactory.getBeanNamesForType(AuthenticationManager.class);

		RootBeanDefinition authenticationMechanism = (RootBeanDefinition) beanFactory.getBeanDefinition(authManager[0]);

		if (authManager.length > 0)
			def.getPropertyValues().addPropertyValue("authenticationManager", authenticationMechanism);
	}
}
