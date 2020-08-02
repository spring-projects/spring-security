/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.config.authentication;

import org.junit.After;
import org.junit.Test;

import org.springframework.beans.FatalBeanException;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Luke Taylor
 */
public class UserServiceBeanDefinitionParserTests {

	private AbstractXmlApplicationContext appContext;

	@After
	public void closeAppContext() {
		if (this.appContext != null) {
			this.appContext.close();
		}
	}

	@Test
	public void userServiceWithValidPropertiesFileWorksSuccessfully() {
		setContext("<user-service id='service' "
				+ "properties='classpath:org/springframework/security/config/users.properties'/>");
		UserDetailsService userService = (UserDetailsService) this.appContext.getBean("service");
		userService.loadUserByUsername("bob");
		userService.loadUserByUsername("joe");
	}

	@Test
	public void userServiceWithEmbeddedUsersWorksSuccessfully() {
		setContext("<user-service id='service'>" + "    <user name='joe' password='joespassword' authorities='ROLE_A'/>"
				+ "</user-service>");
		UserDetailsService userService = (UserDetailsService) this.appContext.getBean("service");
		userService.loadUserByUsername("joe");
	}

	@Test
	public void namePasswordAndAuthoritiesSupportPlaceholders() {
		System.setProperty("principal.name", "joe");
		System.setProperty("principal.pass", "joespassword");
		System.setProperty("principal.authorities", "ROLE_A,ROLE_B");
		setContext("<b:bean class='org.springframework.beans.factory.config.PropertyPlaceholderConfigurer'/>"
				+ "<user-service id='service'>"
				+ "    <user name='${principal.name}' password='${principal.pass}' authorities='${principal.authorities}'/>"
				+ "</user-service>");
		UserDetailsService userService = (UserDetailsService) this.appContext.getBean("service");
		UserDetails joe = userService.loadUserByUsername("joe");
		assertThat(joe.getPassword()).isEqualTo("joespassword");
		assertThat(joe.getAuthorities()).hasSize(2);
	}

	@Test
	public void embeddedUsersWithNoPasswordIsGivenGeneratedValue() {
		setContext("<user-service id='service'>" + "    <user name='joe' authorities='ROLE_A'/>" + "</user-service>");
		UserDetailsService userService = (UserDetailsService) this.appContext.getBean("service");
		UserDetails joe = userService.loadUserByUsername("joe");
		assertThat(joe.getPassword().length() > 0).isTrue();
		Long.parseLong(joe.getPassword());
	}

	@Test
	public void worksWithOpenIDUrlsAsNames() {
		setContext("<user-service id='service'>" + "    <user name='https://joe.myopenid.com/' authorities='ROLE_A'/>"
				+ "    <user name='https://www.google.com/accounts/o8/id?id=MPtOaenBIk5yzW9n7n9' authorities='ROLE_A'/>"
				+ "</user-service>");
		UserDetailsService userService = (UserDetailsService) this.appContext.getBean("service");
		assertThat(userService.loadUserByUsername("https://joe.myopenid.com/").getUsername())
				.isEqualTo("https://joe.myopenid.com/");
		assertThat(userService.loadUserByUsername("https://www.google.com/accounts/o8/id?id=MPtOaenBIk5yzW9n7n9")
				.getUsername()).isEqualTo("https://www.google.com/accounts/o8/id?id=MPtOaenBIk5yzW9n7n9");
	}

	@Test
	public void disabledAndEmbeddedFlagsAreSupported() {
		setContext("<user-service id='service'>"
				+ "    <user name='joe' password='joespassword' authorities='ROLE_A' locked='true'/>"
				+ "    <user name='Bob' password='bobspassword' authorities='ROLE_A' disabled='true'/>"
				+ "</user-service>");
		UserDetailsService userService = (UserDetailsService) this.appContext.getBean("service");
		UserDetails joe = userService.loadUserByUsername("joe");
		assertThat(joe.isAccountNonLocked()).isFalse();
		// Check case-sensitive lookup SEC-1432
		UserDetails bob = userService.loadUserByUsername("Bob");
		assertThat(bob.isEnabled()).isFalse();
	}

	@Test(expected = FatalBeanException.class)
	public void userWithBothPropertiesAndEmbeddedUsersThrowsException() {
		setContext("<user-service id='service' properties='doesntmatter.props'>"
				+ "    <user name='joe' password='joespassword' authorities='ROLE_A'/>" + "</user-service>");
		UserDetailsService userService = (UserDetailsService) this.appContext.getBean("service");
		userService.loadUserByUsername("Joe");
	}

	@Test(expected = FatalBeanException.class)
	public void multipleTopLevelUseWithoutIdThrowsException() {
		setContext("<user-service properties='classpath:org/springframework/security/config/users.properties'/>"
				+ "<user-service properties='classpath:org/springframework/security/config/users.properties'/>");
	}

	@Test(expected = FatalBeanException.class)
	public void userServiceWithMissingPropertiesFileThrowsException() {
		setContext("<user-service id='service' properties='classpath:doesntexist.properties'/>");
	}

	private void setContext(String context) {
		this.appContext = new InMemoryXmlApplicationContext(context);
	}

}
