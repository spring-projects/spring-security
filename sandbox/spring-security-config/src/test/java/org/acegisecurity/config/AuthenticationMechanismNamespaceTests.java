/**
 * 
 */
package org.acegisecurity.config;

import org.acegisecurity.providers.ProviderManager;
import org.acegisecurity.providers.dao.DaoAuthenticationProvider;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import junit.framework.TestCase;

/**
 * @author vpuri
 * 
 */
public class AuthenticationMechanismNamespaceTests extends TestCase {
	public void testParserDefaults() {
		ApplicationContext context = new ClassPathXmlApplicationContext(
				"org/acegisecurity/config/remember-me-defaults.xml");
		ProviderManager mgr = (ProviderManager) context.getBean("authenticationManager");
		assertEquals(1, mgr.getProviders().size());
		assertTrue(mgr.getProviders().get(0) instanceof DaoAuthenticationProvider);
	}
}
