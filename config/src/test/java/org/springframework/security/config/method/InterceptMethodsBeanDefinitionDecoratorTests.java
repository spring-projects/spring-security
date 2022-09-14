/*
 * Copyright 2002-2022 the original author or authors.
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

import org.aopalliance.intercept.MethodInvocation;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

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
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.config.TestBusinessBean;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

/**
 * @author Luke Taylor
 */
@ExtendWith(SpringExtension.class)
@ContextConfiguration(locations = "classpath:org/springframework/security/config/method-security.xml")
public class InterceptMethodsBeanDefinitionDecoratorTests implements ApplicationContextAware {

	@Autowired
	@Qualifier("target")
	private TestBusinessBean target;

	@Autowired
	@Qualifier("transactionalTarget")
	private TestBusinessBean transactionalTarget;

	@Autowired
	@Qualifier("targetAuthorizationManager")
	private TestBusinessBean targetAuthorizationManager;

	@Autowired
	@Qualifier("transactionalTargetAuthorizationManager")
	private TestBusinessBean transactionalTargetAuthorizationManager;

	@Autowired
	@Qualifier("targetCustomAuthorizationManager")
	private TestBusinessBean targetCustomAuthorizationManager;

	@Autowired
	private AuthorizationManager<MethodInvocation> mockAuthorizationManager;

	private ApplicationContext appContext;

	@BeforeAll
	public static void loadContext() {
		// Set value for placeholder
		System.setProperty("admin.role", "ROLE_ADMIN");
	}

	@AfterEach
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void targetDoesntLoseApplicationListenerInterface() {
		assertThat(this.appContext.getBeansOfType(ApplicationListener.class)).isNotEmpty();
		assertThat(this.appContext.getBeanNamesForType(ApplicationListener.class)).isNotEmpty();
		this.appContext.publishEvent(new AuthenticationSuccessEvent(new TestingAuthenticationToken("user", "")));
		assertThat(this.target).isInstanceOf(ApplicationListener.class);
		assertThat(this.targetAuthorizationManager).isInstanceOf(ApplicationListener.class);
		assertThat(this.targetCustomAuthorizationManager).isInstanceOf(ApplicationListener.class);
	}

	@Test
	public void targetShouldAllowUnprotectedMethodInvocationWithNoContext() {
		this.target.unprotected();
	}

	@Test
	public void targetShouldPreventProtectedMethodInvocationWithNoContext() {
		assertThatExceptionOfType(AuthenticationCredentialsNotFoundException.class)
				.isThrownBy(this.target::doSomething);
	}

	@Test
	public void targetShouldAllowProtectedMethodInvocationWithCorrectRole() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.authenticated("Test",
				"Password", AuthorityUtils.createAuthorityList("ROLE_USER"));
		SecurityContextHolder.getContext().setAuthentication(token);
		this.target.doSomething();
	}

	@Test
	public void targetShouldPreventProtectedMethodInvocationWithIncorrectRole() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.authenticated("Test",
				"Password", AuthorityUtils.createAuthorityList("ROLE_SOMEOTHERROLE"));
		SecurityContextHolder.getContext().setAuthentication(token);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.target::doSomething);
	}

	@Test
	public void transactionalMethodsShouldBeSecured() {
		assertThatExceptionOfType(AuthenticationException.class).isThrownBy(this.transactionalTarget::doSomething);
	}

	@Test
	public void targetAuthorizationManagerShouldAllowUnprotectedMethodInvocationWithNoContext() {
		this.targetAuthorizationManager.unprotected();
	}

	@Test
	public void targetAuthorizationManagerShouldPreventProtectedMethodInvocationWithNoContext() {
		assertThatExceptionOfType(AuthenticationCredentialsNotFoundException.class)
				.isThrownBy(this.targetAuthorizationManager::doSomething);
	}

	@Test
	public void targetAuthorizationManagerShouldAllowProtectedMethodInvocationWithCorrectRole() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.authenticated("Test",
				"Password", AuthorityUtils.createAuthorityList("ROLE_USER"));
		SecurityContextHolder.getContext().setAuthentication(token);
		this.targetAuthorizationManager.doSomething();
	}

	@Test
	public void targetAuthorizationManagerShouldPreventProtectedMethodInvocationWithIncorrectRole() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.authenticated("Test",
				"Password", AuthorityUtils.createAuthorityList("ROLE_SOMEOTHERROLE"));
		SecurityContextHolder.getContext().setAuthentication(token);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(this.targetAuthorizationManager::doSomething);
	}

	@Test
	public void transactionalAuthorizationManagerMethodsShouldBeSecured() {
		assertThatExceptionOfType(AuthenticationException.class)
				.isThrownBy(this.transactionalTargetAuthorizationManager::doSomething);
	}

	@Test
	public void targetCustomAuthorizationManagerUsed() {
		given(this.mockAuthorizationManager.check(any(), any())).willReturn(new AuthorizationDecision(true));
		this.targetCustomAuthorizationManager.doSomething();
		verify(this.mockAuthorizationManager).check(any(), any());
	}

	@Override
	public void setApplicationContext(ApplicationContext applicationContext) throws BeansException {
		this.appContext = applicationContext;
	}

}
