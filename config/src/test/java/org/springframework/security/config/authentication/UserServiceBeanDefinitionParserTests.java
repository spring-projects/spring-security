/*
 * Copyright 2004-present the original author or authors.
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

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import org.springframework.beans.FatalBeanException;
import org.springframework.context.support.AbstractXmlApplicationContext;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Luke Taylor
 */
public class UserServiceBeanDefinitionParserTests {

	private AbstractXmlApplicationContext appContext;

	@AfterEach
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
		// @formatter:off
		setContext("<user-service id='service'>"
				+ "    <user name='joe' password='joespassword' authorities='ROLE_A'/>"
				+ "</user-service>");
		// @formatter:on
		UserDetailsService userService = (UserDetailsService) this.appContext.getBean("service");
		userService.loadUserByUsername("joe");
	}

	@Test
	public void namePasswordAndAuthoritiesSupportPlaceholders() {
		System.setProperty("principal.name", "joe");
		System.setProperty("principal.pass", "joespassword");
		System.setProperty("principal.authorities", "ROLE_A,ROLE_B");
		// @formatter:off
		setContext("<b:bean class='org.springframework.context.support.PropertySourcesPlaceholderConfigurer'/>"
				+ "<user-service id='service'>"
				+ "    <user name='${principal.name}' password='${principal.pass}' authorities='${principal.authorities}'/>"
				+ "</user-service>");
		// @formatter:on
		UserDetailsService userService = (UserDetailsService) this.appContext.getBean("service");
		UserDetails joe = userService.loadUserByUsername("joe");
		assertThat(joe.getPassword()).isEqualTo("joespassword");
		assertThat(joe.getAuthorities()).hasSize(2);
	}

	@Test
	public void embeddedUsersWithNoPasswordIsGivenGeneratedValue() {
		// @formatter:off
		setContext("<user-service id='service'>"
				+ "    <user name='joe' authorities='ROLE_A'/>"
				+ "</user-service>");
		// @formatter:on
		UserDetailsService userService = (UserDetailsService) this.appContext.getBean("service");
		UserDetails joe = userService.loadUserByUsername("joe");
		assertThat(joe.getPassword().length() > 0).isTrue();
		Long.parseLong(joe.getPassword());
	}

	@Test
	public void disabledAndEmbeddedFlagsAreSupported() {
		// @formatter:off
		setContext("<user-service id='service'>"
				+ "    <user name='joe' password='joespassword' authorities='ROLE_A' locked='true'/>"
				+ "    <user name='Bob' password='bobspassword' authorities='ROLE_A' disabled='true'/>"
				+ "</user-service>");
		// @formatter:on
		UserDetailsService userService = (UserDetailsService) this.appContext.getBean("service");
		UserDetails joe = userService.loadUserByUsername("joe");
		assertThat(joe.isAccountNonLocked()).isFalse();
		// Check case-sensitive lookup SEC-1432
		UserDetails bob = userService.loadUserByUsername("Bob");
		assertThat(bob.isEnabled()).isFalse();
	}

	@Test
	public void userWithBothPropertiesAndEmbeddedUsersThrowsException() {
		assertThatExceptionOfType(FatalBeanException.class).isThrownBy(() ->
		// @formatter:off
			setContext("<user-service id='service' properties='doesntmatter.props'>"
					+ "    <user name='joe' password='joespassword' authorities='ROLE_A'/>"
					+ "</user-service>")
		// @formatter:on
		);
	}

	@Test
	public void multipleTopLevelUseWithoutIdThrowsException() {
		assertThatExceptionOfType(FatalBeanException.class).isThrownBy(() -> setContext(
				"<user-service properties='classpath:org/springframework/security/config/users.properties'/>"
						+ "<user-service properties='classpath:org/springframework/security/config/users.properties'/>"));
	}

	@Test
	public void userServiceWithMissingPropertiesFileThrowsException() {
		assertThatExceptionOfType(FatalBeanException.class)
			.isThrownBy(() -> setContext("<user-service id='service' properties='classpath:doesntexist.properties'/>"));
	}

	private void setContext(String context) {
		this.appContext = new InMemoryXmlApplicationContext(context);
	}

}
