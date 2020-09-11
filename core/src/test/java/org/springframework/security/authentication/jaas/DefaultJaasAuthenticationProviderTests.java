/*
 * Copyright 2010-2016 the original author or authors.
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

package org.springframework.security.authentication.jaas;

import java.util.Arrays;
import java.util.Collections;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.AppConfigurationEntry.LoginModuleControlFlag;
import javax.security.auth.login.Configuration;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.apache.commons.logging.Log;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.jaas.event.JaasAuthenticationFailedEvent;
import org.springframework.security.authentication.jaas.event.JaasAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.session.SessionDestroyedEvent;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

public class DefaultJaasAuthenticationProviderTests {

	private DefaultJaasAuthenticationProvider provider;

	private UsernamePasswordAuthenticationToken token;

	private ApplicationEventPublisher publisher;

	private Log log;

	@Before
	public void setUp() throws Exception {
		Configuration configuration = mock(Configuration.class);
		this.publisher = mock(ApplicationEventPublisher.class);
		this.log = mock(Log.class);
		this.provider = new DefaultJaasAuthenticationProvider();
		this.provider.setConfiguration(configuration);
		this.provider.setApplicationEventPublisher(this.publisher);
		this.provider.setAuthorityGranters(new AuthorityGranter[] { new TestAuthorityGranter() });
		this.provider.afterPropertiesSet();
		AppConfigurationEntry[] aces = new AppConfigurationEntry[] {
				new AppConfigurationEntry(TestLoginModule.class.getName(), LoginModuleControlFlag.REQUIRED,
						Collections.<String, Object>emptyMap()) };
		given(configuration.getAppConfigurationEntry(this.provider.getLoginContextName())).willReturn(aces);
		this.token = new UsernamePasswordAuthenticationToken("user", "password");
		ReflectionTestUtils.setField(this.provider, "log", this.log);
	}

	@Test
	public void afterPropertiesSetNullConfiguration() throws Exception {
		this.provider.setConfiguration(null);
		assertThatIllegalArgumentException().isThrownBy(this.provider::afterPropertiesSet);
	}

	@Test
	public void afterPropertiesSetNullAuthorityGranters() throws Exception {
		this.provider.setAuthorityGranters(null);
		assertThatIllegalArgumentException().isThrownBy(this.provider::afterPropertiesSet);
	}

	@Test
	public void authenticateUnsupportedAuthentication() {
		assertThat(this.provider.authenticate(new TestingAuthenticationToken("user", "password"))).isNull();
	}

	@Test
	public void authenticateSuccess() {
		Authentication auth = this.provider.authenticate(this.token);
		assertThat(auth.getPrincipal()).isEqualTo(this.token.getPrincipal());
		assertThat(auth.getCredentials()).isEqualTo(this.token.getCredentials());
		assertThat(auth.isAuthenticated()).isEqualTo(true);
		assertThat(auth.getAuthorities().isEmpty()).isEqualTo(false);
		verify(this.publisher).publishEvent(isA(JaasAuthenticationSuccessEvent.class));
		verifyNoMoreInteractions(this.publisher);
	}

	@Test
	public void authenticateBadPassword() {
		assertThatExceptionOfType(AuthenticationException.class)
				.isThrownBy(() -> this.provider.authenticate(new UsernamePasswordAuthenticationToken("user", "asdf")));
		verifyFailedLogin();
	}

	@Test
	public void authenticateBadUser() {
		assertThatExceptionOfType(AuthenticationException.class).isThrownBy(
				() -> this.provider.authenticate(new UsernamePasswordAuthenticationToken("asdf", "password")));
		verifyFailedLogin();
	}

	@Test
	public void logout() throws Exception {
		SessionDestroyedEvent event = mock(SessionDestroyedEvent.class);
		SecurityContext securityContext = mock(SecurityContext.class);
		JaasAuthenticationToken token = mock(JaasAuthenticationToken.class);
		LoginContext context = mock(LoginContext.class);
		given(event.getSecurityContexts()).willReturn(Arrays.asList(securityContext));
		given(securityContext.getAuthentication()).willReturn(token);
		given(token.getLoginContext()).willReturn(context);
		this.provider.onApplicationEvent(event);
		verify(event).getSecurityContexts();
		verify(securityContext).getAuthentication();
		verify(token).getLoginContext();
		verify(context).logout();
		verifyNoMoreInteractions(event, securityContext, token, context);
	}

	@Test
	public void logoutNullSession() {
		SessionDestroyedEvent event = mock(SessionDestroyedEvent.class);
		this.provider.handleLogout(event);
		verify(event).getSecurityContexts();
		verify(this.log).debug(anyString());
		verifyNoMoreInteractions(event);
	}

	@Test
	public void logoutNullAuthentication() {
		SessionDestroyedEvent event = mock(SessionDestroyedEvent.class);
		SecurityContext securityContext = mock(SecurityContext.class);
		given(event.getSecurityContexts()).willReturn(Arrays.asList(securityContext));
		this.provider.handleLogout(event);
		verify(event).getSecurityContexts();
		verify(event).getSecurityContexts();
		verify(securityContext).getAuthentication();
		verifyNoMoreInteractions(event, securityContext);
	}

	@Test
	public void logoutNonJaasAuthentication() {
		SessionDestroyedEvent event = mock(SessionDestroyedEvent.class);
		SecurityContext securityContext = mock(SecurityContext.class);
		given(event.getSecurityContexts()).willReturn(Arrays.asList(securityContext));
		given(securityContext.getAuthentication()).willReturn(this.token);
		this.provider.handleLogout(event);
		verify(event).getSecurityContexts();
		verify(event).getSecurityContexts();
		verify(securityContext).getAuthentication();
		verifyNoMoreInteractions(event, securityContext);
	}

	@Test
	public void logoutNullLoginContext() {
		SessionDestroyedEvent event = mock(SessionDestroyedEvent.class);
		SecurityContext securityContext = mock(SecurityContext.class);
		JaasAuthenticationToken token = mock(JaasAuthenticationToken.class);
		given(event.getSecurityContexts()).willReturn(Arrays.asList(securityContext));
		given(securityContext.getAuthentication()).willReturn(token);
		this.provider.onApplicationEvent(event);
		verify(event).getSecurityContexts();
		verify(securityContext).getAuthentication();
		verify(token).getLoginContext();
		verifyNoMoreInteractions(event, securityContext, token);
	}

	@Test
	public void logoutLoginException() throws Exception {
		SessionDestroyedEvent event = mock(SessionDestroyedEvent.class);
		SecurityContext securityContext = mock(SecurityContext.class);
		JaasAuthenticationToken token = mock(JaasAuthenticationToken.class);
		LoginContext context = mock(LoginContext.class);
		LoginException loginException = new LoginException("Failed Login");
		given(event.getSecurityContexts()).willReturn(Arrays.asList(securityContext));
		given(securityContext.getAuthentication()).willReturn(token);
		given(token.getLoginContext()).willReturn(context);
		willThrow(loginException).given(context).logout();
		this.provider.onApplicationEvent(event);
		verify(event).getSecurityContexts();
		verify(securityContext).getAuthentication();
		verify(token).getLoginContext();
		verify(context).logout();
		verify(this.log).warn(anyString(), eq(loginException));
		verifyNoMoreInteractions(event, securityContext, token, context);
	}

	@Test
	public void publishNullPublisher() {
		this.provider.setApplicationEventPublisher(null);
		AuthenticationException ae = new BadCredentialsException("Failed to login");
		this.provider.publishFailureEvent(this.token, ae);
		this.provider.publishSuccessEvent(this.token);
	}

	@Test
	public void javadocExample() {
		String resName = "/" + getClass().getName().replace('.', '/') + ".xml";
		ClassPathXmlApplicationContext context = new ClassPathXmlApplicationContext(resName);
		context.registerShutdownHook();
		try {
			this.provider = context.getBean(DefaultJaasAuthenticationProvider.class);
			Authentication auth = this.provider.authenticate(this.token);
			assertThat(auth.isAuthenticated()).isEqualTo(true);
			assertThat(auth.getPrincipal()).isEqualTo(this.token.getPrincipal());
		}
		finally {
			context.close();
		}
	}

	private void verifyFailedLogin() {
		ArgumentCaptor<JaasAuthenticationFailedEvent> event = ArgumentCaptor
				.forClass(JaasAuthenticationFailedEvent.class);
		verify(this.publisher).publishEvent(event.capture());
		assertThat(event.getValue()).isInstanceOf(JaasAuthenticationFailedEvent.class);
		assertThat(event.getValue().getException()).isNotNull();
		verifyNoMoreInteractions(this.publisher);
	}

}
