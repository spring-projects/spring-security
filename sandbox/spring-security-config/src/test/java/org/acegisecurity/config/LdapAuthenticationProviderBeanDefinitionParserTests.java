package org.acegisecurity.config;

import junit.framework.TestCase;

import org.acegisecurity.ldap.InitialDirContextFactory;
import org.acegisecurity.providers.ldap.LdapAuthenticationProvider;
import org.acegisecurity.providers.ldap.authenticator.BindAuthenticator;
import org.springframework.beans.PropertyValue;
import org.springframework.beans.PropertyValues;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.config.ConstructorArgumentValues.ValueHolder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

/**
 * @author Vishal Puri
 * 
 */
public class LdapAuthenticationProviderBeanDefinitionParserTests extends TestCase {

	public void testBeanDefinitionCreation() {
		ApplicationContext context = new ClassPathXmlApplicationContext("org/acegisecurity/config/ldap-config.xml");
		ConfigurableListableBeanFactory bf = (ConfigurableListableBeanFactory) context.getAutowireCapableBeanFactory();
		BeanDefinition def = (RootBeanDefinition) bf.getBeanDefinition("authenticationManager");
		assertNotNull(def);
		PropertyValues values = def.getPropertyValues();
		PropertyValue value = values.getPropertyValue("providers");
		assertNotNull(value);
		ManagedList list = (ManagedList) value.getValue();
		assertEquals(1, list.size());

		RootBeanDefinition definition = (RootBeanDefinition) list.get(0);
		assertEquals(LdapAuthenticationProvider.class, definition.getBeanClass());

		assertEquals(2, definition.getConstructorArgumentValues().getArgumentCount());

		ValueHolder holder = definition.getConstructorArgumentValues().getArgumentValue(0, BindAuthenticator.class);
		assertNotNull(holder.getConvertedValue() instanceof BindAuthenticator);
		RootBeanDefinition authenticatorDefinition = (RootBeanDefinition) holder.getValue();
		assertEquals(1, authenticatorDefinition.getConstructorArgumentValues().getArgumentCount());

		RootBeanDefinition initialContextDir = (RootBeanDefinition) authenticatorDefinition
				.getConstructorArgumentValues().getArgumentValue(0, InitialDirContextFactory.class).getValue();
		assertEquals("cn=manager,dc=acegisecurity,dc=org", initialContextDir.getPropertyValues().getPropertyValue(
				"managerDn").getValue());
		assertEquals("ldap://monkeymachine:389/dc=acegisecurity,dc=org", initialContextDir.getConstructorArgumentValues()
				.getArgumentValue(0, String.class).getValue());
	}
}
