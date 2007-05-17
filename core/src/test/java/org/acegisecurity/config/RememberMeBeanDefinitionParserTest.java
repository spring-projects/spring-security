package org.acegisecurity.config;

import junit.framework.TestCase;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

public class RememberMeBeanDefinitionParserTest extends TestCase {
	
	public void testParserDefaults() {
		ApplicationContext context = new ClassPathXmlApplicationContext("org/acegisecurity/config/principal-repository-properties.xml");
		
		
	}

}
