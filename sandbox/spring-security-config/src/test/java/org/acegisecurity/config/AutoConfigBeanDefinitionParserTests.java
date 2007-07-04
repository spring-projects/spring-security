/**
 * 
 */
package org.acegisecurity.config;

import java.lang.reflect.Field;
import java.util.Map;

import junit.framework.TestCase;

import org.acegisecurity.AuthenticationManager;
import org.acegisecurity.context.HttpSessionContextIntegrationFilter;
import org.acegisecurity.intercept.method.MethodDefinitionSource;
import org.acegisecurity.intercept.method.aopalliance.MethodDefinitionSourceAdvisor;
import org.acegisecurity.ui.logout.LogoutFilter;
import org.acegisecurity.ui.logout.LogoutHandler;
import org.acegisecurity.ui.rememberme.RememberMeProcessingFilter;
import org.acegisecurity.ui.rememberme.RememberMeServices;
import org.acegisecurity.ui.webapp.AuthenticationProcessingFilter;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.util.ReflectionUtils;

/**
 * @author Vishal Puri
 * 
 */
public class AutoConfigBeanDefinitionParserTests extends TestCase {

	private ApplicationContext context;

	private ConfigurableListableBeanFactory bf;

	// ~ Methods
	// ========================================================================================================

	public void setUp() {
		this.context = new ClassPathXmlApplicationContext("org/acegisecurity/config/auto-config.xml");
		this.bf = (ConfigurableListableBeanFactory) context.getAutowireCapableBeanFactory();
	}

	public void testContextBeanDefinitionCreated() {
		String[] names = bf.getBeanNamesForType(HttpSessionContextIntegrationFilter.class);
		assertEquals(1, names.length);
		HttpSessionContextIntegrationFilter filter = (HttpSessionContextIntegrationFilter) bf.getBean(names[0]);
		// check properties
		// get the bean
		assertTrue(filter.isAllowSessionCreation());
		assertFalse(filter.isForceEagerSessionCreation());
		assertFalse(filter.isCloneFromHttpSession());
	}

	public void testLogoutFilterDefinitionCreatedWithDefaults() throws Exception {
		String[] names = bf.getBeanNamesForType(LogoutFilter.class);
		assertEquals(1, names.length);
		LogoutFilter filter = (LogoutFilter) context.getBean(names[0]);
		assertNotNull(filter);
		Field logoutSuccessUrl = makeAccessibleAndGetFieldByName(filter.getClass().getDeclaredFields(),
				"logoutSuccessUrl");
		String value = (String) logoutSuccessUrl.get(filter);
		assertEquals("/", value);
		Field handlers = makeAccessibleAndGetFieldByName(filter.getClass().getDeclaredFields(), "handlers");
		assertNotNull(handlers);
		LogoutHandler[] handlersArray = (LogoutHandler[]) handlers.get(filter);
		assertEquals(2, handlersArray.length);
	}

	public void testExceptionTranslationFilterCreatedwithDefaults() throws Exception {
		Map map = bf.getBeansOfType(AuthenticationProcessingFilter.class);
		AuthenticationProcessingFilter filter = (AuthenticationProcessingFilter) map.values().iterator().next();
		AuthenticationManager authMgr = filter.getAuthenticationManager();
		assertNotNull(authMgr);
		RememberMeServices remMeServices = filter.getRememberMeServices();
		assertNotNull(remMeServices);
		assertEquals("/acegilogin.jsp?login_error=1", filter.getAuthenticationFailureUrl());
		assertEquals("/", filter.getDefaultTargetUrl());
	}

	public void testRememberMePRocessingFilterCreatedWithDefaults() {
		Map map = bf.getBeansOfType(RememberMeProcessingFilter.class);
		RememberMeProcessingFilter filter = (RememberMeProcessingFilter) map.values().iterator().next();
	}

	public void testMethodDefinitionSourceAdvisorCreatedWithDefaults() throws Exception {
		Map map = bf.getBeansOfType(MethodDefinitionSourceAdvisor.class);
		assertEquals(1, map.size());
		MethodDefinitionSourceAdvisor advisor = (MethodDefinitionSourceAdvisor) map.values().iterator().next();
		Field transactionAttributeSource = makeAccessibleAndGetFieldByName(advisor.getClass().getDeclaredFields(), "transactionAttributeSource");
		assertNotNull(transactionAttributeSource);
		assertTrue(transactionAttributeSource.get(advisor) instanceof MethodDefinitionSource);
	}

	private Field makeAccessibleAndGetFieldByName(Field[] declaredFields, String name) {
		Field field = null;
		for (int i = 0, n = declaredFields.length; i < n; i++) {
			ReflectionUtils.makeAccessible(declaredFields[i]);
			if (declaredFields[i].getName().equals(name)) {
				return declaredFields[i];
			}
		}
		return field;
	}

}
