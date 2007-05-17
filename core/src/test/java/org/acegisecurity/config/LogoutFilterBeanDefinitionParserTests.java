/**
 * 
 */
package org.acegisecurity.config;

import java.util.Map;

import junit.framework.TestCase;

import org.acegisecurity.ui.logout.LogoutHandler;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

/**
 * @author vpuri
 * 
 */
public class LogoutFilterBeanDefinitionParserTests extends TestCase {

	public void testLogoutFilter() {
		ApplicationContext context = new ClassPathXmlApplicationContext(
				"org/acegisecurity/config/logout-filter-with-handlers.xml");
		ConfigurableListableBeanFactory bf = (ConfigurableListableBeanFactory) context.getAutowireCapableBeanFactory();
		Map m = bf.getBeansOfType(LogoutHandler.class);
		assertEquals(2, m.size());
	}

}
