/**
 * 
 */
package org.acegisecurity.config;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

import junit.framework.TestCase;

/**
 * @author vpuri
 *
 */
public class LogoutFilterBeanDefinitionParserTests extends TestCase {
	
	public void testXX(){
		ApplicationContext context = new ClassPathXmlApplicationContext("org/acegisecurity/config/logout-filter-with-handlers.xml");
	}

}
