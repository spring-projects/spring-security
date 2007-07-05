package org.acegisecurity.config;

import java.util.List;

import junit.framework.TestCase;

import org.acegisecurity.AccessDecisionManager;
import org.acegisecurity.vote.AuthenticatedVoter;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

public class AuthorizationManagerBeanDefinitionParserTests extends TestCase {

	public void testParsingBeanDefinition() {
		ApplicationContext context = new ClassPathXmlApplicationContext(
				"org/acegisecurity/config/authorization-manager.xml");
		ConfigurableListableBeanFactory bf = (ConfigurableListableBeanFactory) context.getAutowireCapableBeanFactory();
		String[] beanNames = bf.getBeanNamesForType(AccessDecisionManager.class);
		assertEquals(1, beanNames.length);
		BeanDefinition def = (RootBeanDefinition) bf.getBeanDefinition(beanNames[0]);
		assertNotNull(def);
		List decisionVoters = (ManagedList) def.getPropertyValues().getPropertyValue("decisionVoters").getValue();
		assertEquals(2, decisionVoters.size());
		assertEquals("org.acegisecurity.vote.RoleVoter", ((BeanDefinition) decisionVoters.get(0)).getBeanClassName());
		assertEquals("org.acegisecurity.vote.AuthenticatedVoter", ((BeanDefinition) decisionVoters.get(1)).getBeanClassName());
	}
}
