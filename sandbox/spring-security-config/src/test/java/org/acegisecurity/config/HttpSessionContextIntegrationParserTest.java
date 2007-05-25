/**
 * 
 */
package org.acegisecurity.config;

import javax.servlet.Filter;

import org.acegisecurity.context.HttpSessionContextIntegrationFilter;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;


import junit.framework.TestCase;

/**
 * @author vpuri
 *
 */
public class HttpSessionContextIntegrationParserTest extends TestCase {
	
	public void testApplicationContext() {
		ApplicationContext context = new ClassPathXmlApplicationContext("org/acegisecurity/config/session-context-integration-defaults.xml");
		ConfigurableListableBeanFactory clbf = 
			(ConfigurableListableBeanFactory)context.getAutowireCapableBeanFactory();
		
		String[] names = clbf.getBeanNamesForType(Filter.class);
		assertEquals(1, names.length);
		
		// check bean name
		RootBeanDefinition definition = (RootBeanDefinition)clbf.getBeanDefinition(names[0]);
		assertEquals(HttpSessionContextIntegrationFilter.class, definition.getBeanClass());
		
		// check properties
		//get the bean
		HttpSessionContextIntegrationFilter filter = (HttpSessionContextIntegrationFilter)context.getBean("httpSessionContextIntegrationFilter");
		assertFalse(filter.isAllowSessionCreation());
		assertNotNull(definition.getPropertyValues().getPropertyValue("allowSessionCreation"));
		assertFalse(filter.isForceEagerSessionCreation());
		assertFalse(filter.isCloneFromHttpSession());
	}

}
