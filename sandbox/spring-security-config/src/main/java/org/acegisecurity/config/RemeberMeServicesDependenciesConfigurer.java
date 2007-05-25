/**
 * 
 */
package org.acegisecurity.config;

import org.acegisecurity.ui.rememberme.RememberMeServices;
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
public class RemeberMeServicesDependenciesConfigurer implements BeanFactoryPostProcessor {

	public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
		
		String [] userDetailServices = beanFactory.getBeanNamesForType(UserDetailsService.class);
		
		String [] rememberMeService = beanFactory.getBeanNamesForType(RememberMeServices.class);
		
		RootBeanDefinition definition=(RootBeanDefinition) beanFactory.getBeanDefinition(rememberMeService[0]);
		
		// there should be only one principal-repository defined, pick the first one
		if(userDetailServices.length!=0) {
			definition.getPropertyValues().addPropertyValue("userDetailsService", new RuntimeBeanReference(userDetailServices[0]));
		}
		
	}

}
