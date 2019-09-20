/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.config.method;

import static org.assertj.core.api.Assertions.*;

import org.junit.*;
import org.junit.runner.RunWith;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.context.ApplicationListener;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.config.TestBusinessBean;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * @author Luke Taylor
 */
@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(locations = "classpath:org/springframework/security/config/method-security.xml")
public class InterceptMethodsBeanDefinitionDecoratorTests implements
		ApplicationContextAware {
	@Autowired
	@Qualifier("target")
	private TestBusinessBean target;
	@Autowired
	@Qualifier("transactionalTarget")
	private TestBusinessBean transactionalTarget;
	private ApplicationContext appContext;

	@BeforeClass
	public static void loadContext() {
		// Set value for placeholder
		System.setProperty("admin.role", "ROLE_ADMIN");
	}

	@After
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void targetDoesntLoseApplicationListenerInterface() {
		assertThat(appContext.getBeansOfType(ApplicationListener.class)).hasSize(1);
		assertThat(appContext.getBeanNamesForType(ApplicationListener.class)).hasSize(1);
		appContext.publishEvent(new AuthenticationSuccessEvent(
				new TestingAuthenticationToken("user", "")));

		assertThat(target).isInstanceOf(ApplicationListener.class);
	}

	@Test
	public void targetShouldAllowUnprotectedMethodInvocationWithNoContext() {
		target.unprotected();
	}

	@Test(expected = AuthenticationCredentialsNotFoundException.class)
	public void targetShouldPreventProtectedMethodInvocationWithNoContext() {
		target.doSomething();
	}

	@Test
	public void targetShouldAllowProtectedMethodInvocationWithCorrectRole() {
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
				"Test", "Password", AuthorityUtils.createAuthorityList("ROLE_USER"));
		SecurityContextHolder.getContext().setAuthentication(token);

		target.doSomething();
	}

	@Test(expected = AccessDeniedException.class)
	public void targetShouldPreventProtectedMethodInvocationWithIncorrectRole() {
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(
				"Test", "Password",
				AuthorityUtils.createAuthorityList("ROLE_SOMEOTHERROLE"));
		SecurityContextHolder.getContext().setAuthentication(token);

		target.doSomething();
	}

	@Test(expected = AuthenticationException.class)
	public void transactionalMethodsShouldBeSecured() {
		transactionalTarget.doSomething();
	}

	public void setApplicationContext(ApplicationContext applicationContext)
			throws BeansException {
		this.appContext = applicationContext;
	}
}
