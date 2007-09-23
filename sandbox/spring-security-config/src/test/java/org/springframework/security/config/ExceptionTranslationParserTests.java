package org.springframework.security.config;

import java.lang.reflect.Field;

import junit.framework.TestCase;

import org.springframework.security.ui.AccessDeniedHandler;
import org.springframework.security.ui.AccessDeniedHandlerImpl;
import org.springframework.security.ui.ExceptionTranslationFilter;
import org.springframework.security.ui.webapp.AuthenticationProcessingFilterEntryPoint;
import org.springframework.beans.PropertyValue;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.util.ReflectionUtils;

public class ExceptionTranslationParserTests extends TestCase {

	public void testParsingBeanReferences() {
		ApplicationContext context = new ClassPathXmlApplicationContext(
				"org/springframework/security/config/exception-translation-beanref.xml");
		ConfigurableListableBeanFactory factory = (ConfigurableListableBeanFactory) context
				.getAutowireCapableBeanFactory();
		String[] beanNames = factory.getBeanNamesForType(ExceptionTranslationFilter.class);
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
				"org/springframework/security/config/exception-translation-beanref.xml");
		ExceptionTranslationFilter filter = (ExceptionTranslationFilter) context.getBean("exceptionTranslationFilter");
		AuthenticationProcessingFilterEntryPoint entryPoint = (AuthenticationProcessingFilterEntryPoint) filter
				.getAuthenticationEntryPoint();
		assertEquals("/acegilogin.jsp", entryPoint.getLoginFormUrl());
		assertFalse(entryPoint.getForceHttps());

	}

	public void testAutoDetectionOfDefaultDependencies() throws Exception {
		ApplicationContext context = new ClassPathXmlApplicationContext(
				"org/springframework/security/config/exception-translation-autodetect-handler.xml");
		ExceptionTranslationFilter filter = (ExceptionTranslationFilter) context.getBean("exceptionTranslationFilter");
		Field field = makeAccessibleAndGetFieldByName(filter.getClass().getDeclaredFields(), "accessDeniedHandler");
		assertTrue(field.get(filter) instanceof AccessDeniedHandler);
		AccessDeniedHandlerImpl accessDeniedHandler = (AccessDeniedHandlerImpl) field
				.get(filter);
		Field f = makeAccessibleAndGetFieldByName(accessDeniedHandler.getClass().getDeclaredFields(), "errorPage");
		assertEquals("errorPage",f.getName());
		String value = (String) f.get(accessDeniedHandler);
		assertEquals("/accessDenied.jsp", value);
	}

	private Field makeAccessibleAndGetFieldByName(Field[] fields, String name) {
		Field field = null;
		for (int i = 0, n = fields.length; i < n; i++) {
			ReflectionUtils.makeAccessible(fields[i]);
			if (fields[i].getName().equals(name)) {
				return fields[i];
			}
		}
		return field;
	}

}
