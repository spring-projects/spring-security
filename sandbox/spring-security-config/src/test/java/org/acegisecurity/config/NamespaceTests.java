/**
 * 
 */
package org.acegisecurity.config;

import junit.framework.TestCase;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

/**
 * @author vpuri
 *
 */
public class NamespaceTests extends TestCase {
	
		
	public void testPass() {
		ApplicationContext c = new ClassPathXmlApplicationContext("org/acegisecurity/config/applicationContext-acegi-security.xml");
	}

}
