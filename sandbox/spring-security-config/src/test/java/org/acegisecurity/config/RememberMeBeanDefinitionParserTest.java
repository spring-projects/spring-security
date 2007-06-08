package org.acegisecurity.config;

import junit.framework.TestCase;

import org.acegisecurity.providers.ProviderManager;
import org.acegisecurity.providers.dao.DaoAuthenticationProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

//TODO: fix test name
public class RememberMeBeanDefinitionParserTest extends TestCase {
	
	public void testParserDefaults() {
		ApplicationContext context = new ClassPathXmlApplicationContext("org/acegisecurity/config/remember-me-defaults.xml");
		ProviderManager mgr = (ProviderManager)context.getBean("authenticationManager");
		assertEquals(1, mgr.getProviders().size());
		assertTrue(mgr.getProviders().get(0) instanceof DaoAuthenticationProvider);
	}

}
