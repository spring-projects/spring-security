/**
 * 
 */
package org.acegisecurity.config;

import javax.servlet.Filter;

import junit.framework.TestCase;

import org.acegisecurity.context.HttpSessionContextIntegrationFilter;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

/**
 * @author Vishal Puri
 * 
 */
public class AutoConfigBeanDefinitionParserTests extends TestCase {

	public void testContextBeanDefinitionCreated() {
		ApplicationContext context = new ClassPathXmlApplicationContext("org/acegisecurity/config/auto-config.xml");
		ConfigurableListableBeanFactory bf = (ConfigurableListableBeanFactory) context.getAutowireCapableBeanFactory();
		String[] names = bf.getBeanNamesForType(HttpSessionContextIntegrationFilter.class);
		assertEquals(1, names.length);
		HttpSessionContextIntegrationFilter filter = (HttpSessionContextIntegrationFilter) bf.getBean(names[0]);
		//	check properties
		//get the bean
		assertTrue(filter.isAllowSessionCreation());
		assertFalse(filter.isForceEagerSessionCreation());
		assertFalse(filter.isCloneFromHttpSession());
	}
	
	
}
