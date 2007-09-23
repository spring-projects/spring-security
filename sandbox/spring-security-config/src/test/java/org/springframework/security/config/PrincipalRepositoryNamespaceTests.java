package org.springframework.security.config;

import junit.framework.TestCase;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;
import org.springframework.security.userdetails.User;
import org.springframework.security.userdetails.UserDetailsService;
import org.springframework.security.userdetails.memory.InMemoryDaoImpl;
import org.springframework.security.userdetails.memory.UserMap;
import org.springframework.beans.PropertyValue;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;

/**
 * @author Vishal Puri
 * 
 */
public class PrincipalRepositoryNamespaceTests extends TestCase {

	public void testParserWithUserDefinition() {
		ApplicationContext context = new ClassPathXmlApplicationContext(
				"org/springframework/security/config/principal-repository-user-map.xml");

		ConfigurableListableBeanFactory clbf = (ConfigurableListableBeanFactory) context
				.getAutowireCapableBeanFactory();

		String[] names = clbf.getBeanNamesForType(UserDetailsService.class);
		assertEquals(1, names.length);

		RootBeanDefinition definition = (RootBeanDefinition) clbf.getBeanDefinition(names[0]);
		assertEquals(InMemoryDaoImpl.class, definition.getBeanClass());

		UserMap map = new UserMap();

		GrantedAuthority[] authotities = { new GrantedAuthorityImpl("ROLE_YO"), new GrantedAuthorityImpl("ROLE_YOYO") };

		User user = new User("vishal", "nottellingya", true, true, true, true, authotities);

		map.addUser(user);

		assertPropertyValues(map, definition, "userMap");

	}

	private void assertPropertyValues(UserMap assertionValue, RootBeanDefinition definition, String property) {
		PropertyValue propertyValue = definition.getPropertyValues().getPropertyValue(property);
		assertNotNull(propertyValue);
		assertTrue(propertyValue.getValue() instanceof UserMap);
		UserMap users = (UserMap) propertyValue.getValue();
		assertTrue(assertionValue.getUserCount() == users.getUserCount());
		assertEquals(assertionValue.getUser("vishal"), users.getUser("vishal"));
		assertTrue(users.getUser("vishal").isEnabled());
		assertTrue(users.getUser("vishal").isAccountNonExpired());
		assertTrue(users.getUser("vishal").isAccountNonLocked());
		assertTrue(users.getUser("vishal").isCredentialsNonExpired());
		assertEquals(2, users.getUser("vishal").getAuthorities().length);
		assertEquals(new GrantedAuthorityImpl("ROLE_YO"), users.getUser("vishal").getAuthorities()[0]);
		assertEquals(new GrantedAuthorityImpl("ROLE_YOYO"), users.getUser("vishal").getAuthorities()[1]);
	}

}
