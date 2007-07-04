package org.acegisecurity.config;

import junit.framework.TestCase;

import org.acegisecurity.AccessDecisionManager;
import org.acegisecurity.intercept.web.FilterSecurityInterceptor;
import org.acegisecurity.intercept.web.RegExpBasedFilterInvocationDefinitionMap;
import org.acegisecurity.vote.AffirmativeBased;
import org.springframework.beans.PropertyValue;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

/**
 * @author Vishal Puri
 */
public class FilterSecurityInterceptorBeanDefinitionParserTests extends TestCase {

	public void testParsingBeanDefinition() {
		ApplicationContext context = new ClassPathXmlApplicationContext(
				"org/acegisecurity/config/authorization-http-config.xml");
		ConfigurableListableBeanFactory bf = (ConfigurableListableBeanFactory) context.getAutowireCapableBeanFactory();
		String[] beanNames = bf.getBeanNamesForType(FilterSecurityInterceptor.class);
		assertEquals(1, beanNames.length);
		BeanDefinition def = bf.getBeanDefinition(beanNames[0]);
		assertEquals(2, def.getPropertyValues().size());
		PropertyValue objectDefinitionSource = def.getPropertyValues().getPropertyValue("objectDefinitionSource");
		assertTrue(objectDefinitionSource.getValue() instanceof RegExpBasedFilterInvocationDefinitionMap);
		PropertyValue accessDecisionManager = def.getPropertyValues().getPropertyValue("accessDecisionManager");
		BeanDefinition definition = (RootBeanDefinition) accessDecisionManager.getValue() ;
		assertEquals("org.acegisecurity.vote.AffirmativeBased" , definition.getBeanClassName());
	}
}
