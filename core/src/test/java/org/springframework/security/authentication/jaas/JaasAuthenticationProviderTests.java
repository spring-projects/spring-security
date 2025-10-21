/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.net.URL;
import java.security.Security;
import java.util.Arrays;
import java.util.Collection;
import java.util.Set;

import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.context.ApplicationContext;
import org.springframework.context.support.ClassPathXmlApplicationContext;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.SecurityAssertions;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.session.SessionDestroyedEvent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for the JaasAuthenticationProvider
 *
 * @author Ray Krueger
 */
public class JaasAuthenticationProviderTests {

	private ApplicationContext context;

	private JaasAuthenticationProvider jaasProvider;

	private JaasEventCheck eventCheck;

	@BeforeEach
	public void setUp() {
		String resName = "/" + getClass().getName().replace('.', '/') + ".xml";
		this.context = new ClassPathXmlApplicationContext(resName);
		this.eventCheck = (JaasEventCheck) this.context.getBean("eventCheck");
		this.jaasProvider = (JaasAuthenticationProvider) this.context.getBean("jaasAuthenticationProvider");
	}

	@Test
	public void testBadPassword() {
		assertThatExceptionOfType(AuthenticationException.class).isThrownBy(() -> this.jaasProvider
			.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("user", "asdf")));
		assertThat(this.eventCheck.failedEvent).as("Failure event not fired").isNotNull();
		assertThat(this.eventCheck.failedEvent.getException()).withFailMessage("Failure event exception was null")
			.isNotNull();
		assertThat(this.eventCheck.successEvent).as("Success event was fired").isNull();
	}

	@Test
	public void testBadUser() {
		assertThatExceptionOfType(AuthenticationException.class).isThrownBy(() -> this.jaasProvider
			.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("asdf", "password")));
		assertThat(this.eventCheck.failedEvent).as("Failure event not fired").isNotNull();
		assertThat(this.eventCheck.failedEvent.getException()).withFailMessage("Failure event exception was null")
			.isNotNull();
		assertThat(this.eventCheck.successEvent).as("Success event was fired").isNull();
	}

	@Test
	public void testConfigurationLoop() throws Exception {
		String resName = "/" + getClass().getName().replace('.', '/') + ".conf";
		URL url = getClass().getResource(resName);
		Security.setProperty("login.config.url.1", url.toString());
		setUp();
		testFull();
	}

	@Test
	public void detectsMissingLoginConfig() throws Exception {
		JaasAuthenticationProvider myJaasProvider = new JaasAuthenticationProvider();
		myJaasProvider.setApplicationEventPublisher(this.context);
		myJaasProvider.setAuthorityGranters(this.jaasProvider.getAuthorityGranters());
		myJaasProvider.setCallbackHandlers(this.jaasProvider.getCallbackHandlers());
		myJaasProvider.setLoginContextName(this.jaasProvider.getLoginContextName());
		assertThatIllegalArgumentException().isThrownBy(() -> myJaasProvider.afterPropertiesSet())
			.withMessageStartingWith("loginConfig must be set on");
	}

	// SEC-1239
	@Test
	public void spacesInLoginConfigPathAreAccepted() throws Exception {
		File configFile;
		// Create temp directory with a space in the name
		File configDir = new File(System.getProperty("java.io.tmpdir") + File.separator + "jaas test");
		configDir.deleteOnExit();
		if (configDir.exists()) {
			configDir.delete();
		}
		configDir.mkdir();
		configFile = File.createTempFile("login", "conf", configDir);
		configFile.deleteOnExit();
		FileOutputStream fos = new FileOutputStream(configFile);
		PrintWriter pw = new PrintWriter(fos);
		pw.append(
				"JAASTestBlah {" + "org.springframework.security.authentication.jaas.TestLoginModule required;" + "};");
		pw.flush();
		pw.close();
		JaasAuthenticationProvider myJaasProvider = new JaasAuthenticationProvider();
		myJaasProvider.setApplicationEventPublisher(this.context);
		myJaasProvider.setLoginConfig(new FileSystemResource(configFile));
		myJaasProvider.setAuthorityGranters(this.jaasProvider.getAuthorityGranters());
		myJaasProvider.setCallbackHandlers(this.jaasProvider.getCallbackHandlers());
		myJaasProvider.setLoginContextName(this.jaasProvider.getLoginContextName());
		myJaasProvider.afterPropertiesSet();
	}

	@Test
	public void detectsMissingLoginContextName() throws Exception {
		JaasAuthenticationProvider myJaasProvider = new JaasAuthenticationProvider();
		myJaasProvider.setApplicationEventPublisher(this.context);
		myJaasProvider.setAuthorityGranters(this.jaasProvider.getAuthorityGranters());
		myJaasProvider.setCallbackHandlers(this.jaasProvider.getCallbackHandlers());
		myJaasProvider.setLoginConfig(this.jaasProvider.getLoginConfig());
		myJaasProvider.setLoginContextName(null);
		assertThatIllegalArgumentException().isThrownBy(myJaasProvider::afterPropertiesSet)
			.withMessageStartingWith("loginContextName must be set on");
		myJaasProvider.setLoginContextName("");
		assertThatIllegalArgumentException().isThrownBy(myJaasProvider::afterPropertiesSet)
			.withMessageStartingWith("loginContextName must be set on");
	}

	@Test
	public void testFull() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.authenticated("user",
				"password", AuthorityUtils.createAuthorityList("ROLE_ONE"));
		assertThat(this.jaasProvider.supports(UsernamePasswordAuthenticationToken.class)).isTrue();
		Authentication auth = this.jaasProvider.authenticate(token);
		assertThat(this.jaasProvider.getAuthorityGranters()).isNotNull();
		assertThat(this.jaasProvider.getCallbackHandlers()).isNotNull();
		assertThat(this.jaasProvider.getLoginConfig()).isNotNull();
		assertThat(this.jaasProvider.getLoginContextName()).isNotNull();
		Collection<? extends GrantedAuthority> list = auth.getAuthorities();
		Set<String> set = AuthorityUtils.authorityListToSet(list);
		assertThat(set.contains("ROLE_ONE")).withFailMessage("GrantedAuthorities should not contain ROLE_ONE")
			.isFalse();
		assertThat(set.contains("ROLE_TEST1")).withFailMessage("GrantedAuthorities should contain ROLE_TEST1").isTrue();
		assertThat(set.contains("ROLE_TEST2")).withFailMessage("GrantedAuthorities should contain ROLE_TEST2").isTrue();
		boolean foundit = false;
		for (GrantedAuthority a : list) {
			if (a instanceof JaasGrantedAuthority grant) {
				assertThat(grant.getPrincipal()).withFailMessage("Principal was null on JaasGrantedAuthority")
					.isNotNull();
				foundit = true;
			}
		}
		assertThat(foundit).as("Could not find a JaasGrantedAuthority").isTrue();
		assertThat(this.eventCheck.successEvent).as("Success event should be fired").isNotNull();
		assertThat(this.eventCheck.successEvent.getAuthentication()).withFailMessage("Auth objects should be equal")
			.isEqualTo(auth);
		assertThat(this.eventCheck.failedEvent).as("Failure event should not be fired").isNull();
	}

	@Test
	public void testGetApplicationEventPublisher() {
		assertThat(this.jaasProvider.getApplicationEventPublisher()).isNotNull();
	}

	@Test
	public void testLoginExceptionResolver() {
		assertThat(this.jaasProvider.getLoginExceptionResolver()).isNotNull();
		this.jaasProvider.setLoginExceptionResolver((e) -> new LockedException("This is just a test!"));
		try {
			this.jaasProvider.authenticate(UsernamePasswordAuthenticationToken.unauthenticated("user", "password"));
		}
		catch (LockedException ex) {
		}
		catch (Exception ex) {
			fail("LockedException should have been thrown and caught");
		}
	}

	@Test
	public void testLogout() throws Exception {
		MockLoginContext loginContext = new MockLoginContext(this.jaasProvider.getLoginContextName());
		JaasAuthenticationToken token = new JaasAuthenticationToken(null, null, loginContext);
		SecurityContext context = SecurityContextHolder.createEmptyContext();
		context.setAuthentication(token);
		SessionDestroyedEvent event = mock(SessionDestroyedEvent.class);
		given(event.getSecurityContexts()).willReturn(Arrays.asList(context));
		this.jaasProvider.handleLogout(event);
		assertThat(loginContext.loggedOut).isTrue();
	}

	@Test
	public void testNullDefaultAuthorities() {
		UsernamePasswordAuthenticationToken token = UsernamePasswordAuthenticationToken.unauthenticated("user",
				"password");
		assertThat(this.jaasProvider.supports(UsernamePasswordAuthenticationToken.class)).isTrue();
		Authentication auth = this.jaasProvider.authenticate(token);
		SecurityAssertions.assertThat(auth)
			.roles()
			.withFailMessage("Only ROLE_TEST1 and ROLE_TEST2 should have been returned")
			.hasSize(2);
	}

	@Test
	public void testUnsupportedAuthenticationObjectReturnsNull() {
		assertThat(this.jaasProvider
			.authenticate(new TestingAuthenticationToken("foo", "bar", AuthorityUtils.NO_AUTHORITIES))).isNull();
	}

	@Test
	public void authenticateWhenSuccessThenIssuesFactor() {
		UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken("user", "password");
		Authentication result = this.jaasProvider.authenticate(token);
		SecurityAssertions.assertThat(result).hasAuthority(FactorGrantedAuthority.PASSWORD_AUTHORITY);
	}

	private static class MockLoginContext extends LoginContext {

		boolean loggedOut = false;

		MockLoginContext(String loginModule) throws LoginException {
			super(loginModule);
		}

		@Override
		public void logout() {
			this.loggedOut = true;
		}

	}

}
