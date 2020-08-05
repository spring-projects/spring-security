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

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

import java.util.*;

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
import org.springframework.security.authentication.jaas.DefaultJaasAuthenticationProvider;
import org.springframework.security.authentication.jaas.event.JaasAuthenticationFailedEvent;
import org.springframework.security.authentication.jaas.event.JaasAuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.session.SessionDestroyedEvent;
import org.springframework.test.util.ReflectionTestUtils;

public class DefaultJaasAuthenticationProviderTests {

	private DefaultJaasAuthenticationProvider provider;

	private UsernamePasswordAuthenticationToken token;

	private ApplicationEventPublisher publisher;

	private Log log;

	@Before
	public void setUp() throws Exception {
		Configuration configuration = mock(Configuration.class);
		publisher = mock(ApplicationEventPublisher.class);
		log = mock(Log.class);
		provider = new DefaultJaasAuthenticationProvider();
		provider.setConfiguration(configuration);
		provider.setApplicationEventPublisher(publisher);
		provider.setAuthorityGranters(new AuthorityGranter[] { new TestAuthorityGranter() });
		provider.afterPropertiesSet();
		AppConfigurationEntry[] aces = new AppConfigurationEntry[] {
				new AppConfigurationEntry(TestLoginModule.class.getName(), LoginModuleControlFlag.REQUIRED,
						Collections.<String, Object>emptyMap()) };
		when(configuration.getAppConfigurationEntry(provider.getLoginContextName())).thenReturn(aces);
		token = new UsernamePasswordAuthenticationToken("user", "password");
		ReflectionTestUtils.setField(provider, "log", log);

	}

	@Test(expected = IllegalArgumentException.class)
	public void afterPropertiesSetNullConfiguration() throws Exception {
		provider.setConfiguration(null);
		provider.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void afterPropertiesSetNullAuthorityGranters() throws Exception {
		provider.setAuthorityGranters(null);
		provider.afterPropertiesSet();
	}

	@Test
	public void authenticateUnsupportedAuthentication() {
		assertThat(provider.authenticate(new TestingAuthenticationToken("user", "password"))).isNull();
	}

	@Test
	public void authenticateSuccess() {
		Authentication auth = provider.authenticate(token);
		assertThat(auth.getPrincipal()).isEqualTo(token.getPrincipal());
		assertThat(auth.getCredentials()).isEqualTo(token.getCredentials());
		assertThat(auth.isAuthenticated()).isEqualTo(true);
		assertThat(auth.getAuthorities().isEmpty()).isEqualTo(false);
		verify(publisher).publishEvent(isA(JaasAuthenticationSuccessEvent.class));
		verifyNoMoreInteractions(publisher);
	}

	@Test
	public void authenticateBadPassword() {
		try {
			provider.authenticate(new UsernamePasswordAuthenticationToken("user", "asdf"));
			fail("LoginException should have been thrown for the bad password");
		}
		catch (AuthenticationException success) {
		}

		verifyFailedLogin();
	}

	@Test
	public void authenticateBadUser() {
		try {
			provider.authenticate(new UsernamePasswordAuthenticationToken("asdf", "password"));
			fail("LoginException should have been thrown for the bad user");
		}
		catch (AuthenticationException success) {
		}

		verifyFailedLogin();
	}

	@Test
	public void logout() throws Exception {
		SessionDestroyedEvent event = mock(SessionDestroyedEvent.class);
		SecurityContext securityContext = mock(SecurityContext.class);
		JaasAuthenticationToken token = mock(JaasAuthenticationToken.class);
		LoginContext context = mock(LoginContext.class);

		when(event.getSecurityContexts()).thenReturn(Arrays.asList(securityContext));
		when(securityContext.getAuthentication()).thenReturn(token);
		when(token.getLoginContext()).thenReturn(context);

		provider.onApplicationEvent(event);

		verify(event).getSecurityContexts();
		verify(securityContext).getAuthentication();
		verify(token).getLoginContext();
		verify(context).logout();
		verifyNoMoreInteractions(event, securityContext, token, context);
	}

	@Test
	public void logoutNullSession() {
		SessionDestroyedEvent event = mock(SessionDestroyedEvent.class);

		provider.handleLogout(event);

		verify(event).getSecurityContexts();
		verify(log).debug(anyString());
		verifyNoMoreInteractions(event);
	}

	@Test
	public void logoutNullAuthentication() {
		SessionDestroyedEvent event = mock(SessionDestroyedEvent.class);
		SecurityContext securityContext = mock(SecurityContext.class);

		when(event.getSecurityContexts()).thenReturn(Arrays.asList(securityContext));

		provider.handleLogout(event);

		verify(event).getSecurityContexts();
		verify(event).getSecurityContexts();
		verify(securityContext).getAuthentication();
		verifyNoMoreInteractions(event, securityContext);
	}

	@Test
	public void logoutNonJaasAuthentication() {
		SessionDestroyedEvent event = mock(SessionDestroyedEvent.class);
		SecurityContext securityContext = mock(SecurityContext.class);

		when(event.getSecurityContexts()).thenReturn(Arrays.asList(securityContext));
		when(securityContext.getAuthentication()).thenReturn(token);

		provider.handleLogout(event);

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

		when(event.getSecurityContexts()).thenReturn(Arrays.asList(securityContext));
		when(securityContext.getAuthentication()).thenReturn(token);

		provider.onApplicationEvent(event);
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

		when(event.getSecurityContexts()).thenReturn(Arrays.asList(securityContext));
		when(securityContext.getAuthentication()).thenReturn(token);
		when(token.getLoginContext()).thenReturn(context);
		doThrow(loginException).when(context).logout();

		provider.onApplicationEvent(event);

		verify(event).getSecurityContexts();
		verify(securityContext).getAuthentication();
		verify(token).getLoginContext();
		verify(context).logout();
		verify(log).warn(anyString(), eq(loginException));
		verifyNoMoreInteractions(event, securityContext, token, context);
	}

	@Test
	public void publishNullPublisher() {
		provider.setApplicationEventPublisher(null);
		AuthenticationException ae = new BadCredentialsException("Failed to login");

		provider.publishFailureEvent(token, ae);
		provider.publishSuccessEvent(token);
	}

	@Test
	public void javadocExample() {
		String resName = "/" + getClass().getName().replace('.', '/') + ".xml";
		ClassPathXmlApplicationContext context = new ClassPathXmlApplicationContext(resName);
		context.registerShutdownHook();
		try {
			provider = context.getBean(DefaultJaasAuthenticationProvider.class);
			Authentication auth = provider.authenticate(token);
			assertThat(auth.isAuthenticated()).isEqualTo(true);
			assertThat(auth.getPrincipal()).isEqualTo(token.getPrincipal());
		}
		finally {
			context.close();
		}
	}

	private void verifyFailedLogin() {
		ArgumentCaptor<JaasAuthenticationFailedEvent> event = ArgumentCaptor
				.forClass(JaasAuthenticationFailedEvent.class);
		verify(publisher).publishEvent(event.capture());
		assertThat(event.getValue()).isInstanceOf(JaasAuthenticationFailedEvent.class);
		assertThat(event.getValue().getException()).isNotNull();
		verifyNoMoreInteractions(publisher);
	}

}
