package org.acegisecurity.config;

import javax.servlet.Filter;

import junit.framework.TestCase;

import org.acegisecurity.ui.ExceptionTranslationFilter;
import org.acegisecurity.ui.webapp.AuthenticationProcessingFilterEntryPoint;
import org.springframework.beans.PropertyValue;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

public class ExceptionTranslationParserTests extends TestCase {

	public void testParsingBeanReferences() {
		ApplicationContext context = new ClassPathXmlApplicationContext(
				"org/acegisecurity/config/exception-translation-beanref.xml");
		ConfigurableListableBeanFactory factory = (ConfigurableListableBeanFactory) context
				.getAutowireCapableBeanFactory();
		String[] beanNames = factory.getBeanNamesForType(Filter.class);
		assertEquals(1, beanNames.length);
		RootBeanDefinition def = (RootBeanDefinition) factory.getBeanDefinition(beanNames[0]);
		assertEquals(ExceptionTranslationFilter.class.getName(), def.getBeanClassName());
		// check collaborators
		PropertyValue accessDeniedHandler = def.getPropertyValues().getPropertyValue("accessDeniedHandler");
		assertNotNull(accessDeniedHandler);
		assertEquals(accessDeniedHandler.getValue(), new RuntimeBeanReference("theBeanToUse"));
		PropertyValue entryPoint = def.getPropertyValues().getPropertyValue("authenticationEntryPoint");
		assertNotNull(entryPoint);
		assertEquals(entryPoint.getValue(), new RuntimeBeanReference("authenticationProcessingFilterEntryPoint"));
	}

	public void testRuntimeBeanDependencies() {
		ApplicationContext context = new ClassPathXmlApplicationContext(
				"org/acegisecurity/config/exception-translation-beanref.xml");
		ExceptionTranslationFilter filter = (ExceptionTranslationFilter) context.getBean("exceptionTranslationFilter");
		AuthenticationProcessingFilterEntryPoint entryPoint = (AuthenticationProcessingFilterEntryPoint) filter
				.getAuthenticationEntryPoint();
		assertEquals("/acegilogin.jsp", entryPoint.getLoginFormUrl());
		assertFalse(entryPoint.getForceHttps());

	}

}
