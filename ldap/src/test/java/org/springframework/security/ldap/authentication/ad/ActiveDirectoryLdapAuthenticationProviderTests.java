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
package org.springframework.security.ldap.authentication.ad;

import java.util.Collections;
import java.util.Hashtable;

import javax.naming.AuthenticationException;
import javax.naming.CommunicationException;
import javax.naming.Name;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.apache.directory.shared.ldap.util.EmptyEnumeration;
import org.hamcrest.BaseMatcher;
import org.hamcrest.CoreMatchers;
import org.hamcrest.Description;
import org.hamcrest.Matcher;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;

import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DistinguishedName;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.ldap.authentication.ad.ActiveDirectoryLdapAuthenticationProvider.ContextFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * @author Luke Taylor
 * @author Rob Winch
 */
public class ActiveDirectoryLdapAuthenticationProviderTests {

	public static final String EXISTING_LDAP_PROVIDER = "ldap://192.168.1.200/";

	public static final String NON_EXISTING_LDAP_PROVIDER = "ldap://192.168.1.201/";

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	ActiveDirectoryLdapAuthenticationProvider provider;

	UsernamePasswordAuthenticationToken joe = new UsernamePasswordAuthenticationToken("joe", "password");

	@Before
	public void setUp() {
		this.provider = new ActiveDirectoryLdapAuthenticationProvider("mydomain.eu", "ldap://192.168.1.200/");
	}

	@Test
	public void bindPrincipalIsCreatedCorrectly() {
		assertThat(this.provider.createBindPrincipal("joe")).isEqualTo("joe@mydomain.eu");
		assertThat(this.provider.createBindPrincipal("joe@mydomain.eu")).isEqualTo("joe@mydomain.eu");
	}

	@Test
	public void successfulAuthenticationProducesExpectedAuthorities() throws Exception {
		checkAuthentication("dc=mydomain,dc=eu", this.provider);
	}

	// SEC-1915
	@Test
	public void customSearchFilterIsUsedForSuccessfulAuthentication() throws Exception {
		// given
		String customSearchFilter = "(&(objectClass=user)(sAMAccountName={0}))";

		DirContext ctx = mock(DirContext.class);
		given(ctx.getNameInNamespace()).willReturn("");

		DirContextAdapter dca = new DirContextAdapter();
		SearchResult sr = new SearchResult("CN=Joe Jannsen,CN=Users", dca, dca.getAttributes());
		given(ctx.search(any(Name.class), eq(customSearchFilter), any(Object[].class), any(SearchControls.class)))
				.willReturn(new MockNamingEnumeration(sr));

		ActiveDirectoryLdapAuthenticationProvider customProvider = new ActiveDirectoryLdapAuthenticationProvider(
				"mydomain.eu", "ldap://192.168.1.200/");
		customProvider.contextFactory = createContextFactoryReturning(ctx);

		// when
		customProvider.setSearchFilter(customSearchFilter);
		Authentication result = customProvider.authenticate(this.joe);

		// then
		assertThat(result.isAuthenticated()).isTrue();
	}

	@Test
	public void defaultSearchFilter() throws Exception {
		// given
		final String defaultSearchFilter = "(&(objectClass=user)(userPrincipalName={0}))";

		DirContext ctx = mock(DirContext.class);
		given(ctx.getNameInNamespace()).willReturn("");

		DirContextAdapter dca = new DirContextAdapter();
		SearchResult sr = new SearchResult("CN=Joe Jannsen,CN=Users", dca, dca.getAttributes());
		given(ctx.search(any(Name.class), eq(defaultSearchFilter), any(Object[].class), any(SearchControls.class)))
				.willReturn(new MockNamingEnumeration(sr));

		ActiveDirectoryLdapAuthenticationProvider customProvider = new ActiveDirectoryLdapAuthenticationProvider(
				"mydomain.eu", "ldap://192.168.1.200/");
		customProvider.contextFactory = createContextFactoryReturning(ctx);

		// when
		Authentication result = customProvider.authenticate(this.joe);

		// then
		assertThat(result.isAuthenticated()).isTrue();
		verify(ctx).search(any(DistinguishedName.class), eq(defaultSearchFilter), any(Object[].class),
				any(SearchControls.class));
	}

	// SEC-2897,SEC-2224
	@Test
	public void bindPrincipalAndUsernameUsed() throws Exception {
		// given
		final String defaultSearchFilter = "(&(objectClass=user)(userPrincipalName={0}))";
		ArgumentCaptor<Object[]> captor = ArgumentCaptor.forClass(Object[].class);

		DirContext ctx = mock(DirContext.class);
		given(ctx.getNameInNamespace()).willReturn("");

		DirContextAdapter dca = new DirContextAdapter();
		SearchResult sr = new SearchResult("CN=Joe Jannsen,CN=Users", dca, dca.getAttributes());
		given(ctx.search(any(Name.class), eq(defaultSearchFilter), captor.capture(), any(SearchControls.class)))
				.willReturn(new MockNamingEnumeration(sr));

		ActiveDirectoryLdapAuthenticationProvider customProvider = new ActiveDirectoryLdapAuthenticationProvider(
				"mydomain.eu", "ldap://192.168.1.200/");
		customProvider.contextFactory = createContextFactoryReturning(ctx);

		// when
		Authentication result = customProvider.authenticate(this.joe);

		// then
		assertThat(captor.getValue()).containsExactly("joe@mydomain.eu", "joe");
		assertThat(result.isAuthenticated()).isTrue();
	}

	@Test(expected = IllegalArgumentException.class)
	public void setSearchFilterNull() {
		this.provider.setSearchFilter(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void setSearchFilterEmpty() {
		this.provider.setSearchFilter(" ");
	}

	@Test
	public void nullDomainIsSupportedIfAuthenticatingWithFullUserPrincipal() throws Exception {
		this.provider = new ActiveDirectoryLdapAuthenticationProvider(null, "ldap://192.168.1.200/");
		DirContext ctx = mock(DirContext.class);
		given(ctx.getNameInNamespace()).willReturn("");

		DirContextAdapter dca = new DirContextAdapter();
		SearchResult sr = new SearchResult("CN=Joe Jannsen,CN=Users", dca, dca.getAttributes());
		given(ctx.search(eq(new DistinguishedName("DC=mydomain,DC=eu")), any(String.class), any(Object[].class),
				any(SearchControls.class))).willReturn(new MockNamingEnumeration(sr));
		this.provider.contextFactory = createContextFactoryReturning(ctx);

		try {
			this.provider.authenticate(this.joe);
			fail("Expected BadCredentialsException for user with no domain information");
		}
		catch (BadCredentialsException expected) {
		}

		this.provider.authenticate(new UsernamePasswordAuthenticationToken("joe@mydomain.eu", "password"));
	}

	@Test(expected = BadCredentialsException.class)
	public void failedUserSearchCausesBadCredentials() throws Exception {
		DirContext ctx = mock(DirContext.class);
		given(ctx.getNameInNamespace()).willReturn("");
		given(ctx.search(any(Name.class), any(String.class), any(Object[].class), any(SearchControls.class)))
				.willThrow(new NameNotFoundException());

		this.provider.contextFactory = createContextFactoryReturning(ctx);

		this.provider.authenticate(this.joe);
	}

	// SEC-2017
	@Test(expected = BadCredentialsException.class)
	public void noUserSearchCausesUsernameNotFound() throws Exception {
		DirContext ctx = mock(DirContext.class);
		given(ctx.getNameInNamespace()).willReturn("");
		given(ctx.search(any(Name.class), any(String.class), any(Object[].class), any(SearchControls.class)))
				.willReturn(new EmptyEnumeration<>());

		this.provider.contextFactory = createContextFactoryReturning(ctx);

		this.provider.authenticate(this.joe);
	}

	// SEC-2500
	@Test(expected = BadCredentialsException.class)
	public void sec2500PreventAnonymousBind() {
		this.provider.authenticate(new UsernamePasswordAuthenticationToken("rwinch", ""));
	}

	@SuppressWarnings("unchecked")
	@Test(expected = IncorrectResultSizeDataAccessException.class)
	public void duplicateUserSearchCausesError() throws Exception {
		DirContext ctx = mock(DirContext.class);
		given(ctx.getNameInNamespace()).willReturn("");
		NamingEnumeration<SearchResult> searchResults = mock(NamingEnumeration.class);
		given(searchResults.hasMore()).willReturn(true, true, false);
		SearchResult searchResult = mock(SearchResult.class);
		given(searchResult.getObject()).willReturn(new DirContextAdapter("ou=1"), new DirContextAdapter("ou=2"));
		given(searchResults.next()).willReturn(searchResult);
		given(ctx.search(any(Name.class), any(String.class), any(Object[].class), any(SearchControls.class)))
				.willReturn(searchResults);

		this.provider.contextFactory = createContextFactoryReturning(ctx);

		this.provider.authenticate(this.joe);
	}

	static final String msg = "[LDAP: error code 49 - 80858585: LdapErr: DSID-DECAFF0, comment: AcceptSecurityContext error, data ";

	@Test(expected = BadCredentialsException.class)
	public void userNotFoundIsCorrectlyMapped() {
		this.provider.contextFactory = createContextFactoryThrowing(new AuthenticationException(msg + "525, xxxx]"));
		this.provider.setConvertSubErrorCodesToExceptions(true);
		this.provider.authenticate(this.joe);
	}

	@Test(expected = BadCredentialsException.class)
	public void incorrectPasswordIsCorrectlyMapped() {
		this.provider.contextFactory = createContextFactoryThrowing(new AuthenticationException(msg + "52e, xxxx]"));
		this.provider.setConvertSubErrorCodesToExceptions(true);
		this.provider.authenticate(this.joe);
	}

	@Test(expected = BadCredentialsException.class)
	public void notPermittedIsCorrectlyMapped() {
		this.provider.contextFactory = createContextFactoryThrowing(new AuthenticationException(msg + "530, xxxx]"));
		this.provider.setConvertSubErrorCodesToExceptions(true);
		this.provider.authenticate(this.joe);
	}

	@Test
	public void passwordNeedsResetIsCorrectlyMapped() {
		final String dataCode = "773";
		this.provider.contextFactory = createContextFactoryThrowing(
				new AuthenticationException(msg + dataCode + ", xxxx]"));
		this.provider.setConvertSubErrorCodesToExceptions(true);

		this.thrown.expect(BadCredentialsException.class);
		this.thrown.expect(new BaseMatcher<BadCredentialsException>() {
			private Matcher<Object> causeInstance = CoreMatchers
					.instanceOf(ActiveDirectoryAuthenticationException.class);

			private Matcher<String> causeDataCode = CoreMatchers.equalTo(dataCode);

			@Override
			public boolean matches(Object that) {
				Throwable t = (Throwable) that;
				ActiveDirectoryAuthenticationException cause = (ActiveDirectoryAuthenticationException) t.getCause();
				return this.causeInstance.matches(cause) && this.causeDataCode.matches(cause.getDataCode());
			}

			@Override
			public void describeTo(Description desc) {
				desc.appendText("getCause() ");
				this.causeInstance.describeTo(desc);
				desc.appendText("getCause().getDataCode() ");
				this.causeDataCode.describeTo(desc);
			}
		});

		this.provider.authenticate(this.joe);
	}

	@Test(expected = CredentialsExpiredException.class)
	public void expiredPasswordIsCorrectlyMapped() {
		this.provider.contextFactory = createContextFactoryThrowing(new AuthenticationException(msg + "532, xxxx]"));

		try {
			this.provider.authenticate(this.joe);
			fail("BadCredentialsException should had been thrown");
		}
		catch (BadCredentialsException expected) {
		}

		this.provider.setConvertSubErrorCodesToExceptions(true);
		this.provider.authenticate(this.joe);
	}

	@Test(expected = DisabledException.class)
	public void accountDisabledIsCorrectlyMapped() {
		this.provider.contextFactory = createContextFactoryThrowing(new AuthenticationException(msg + "533, xxxx]"));
		this.provider.setConvertSubErrorCodesToExceptions(true);
		this.provider.authenticate(this.joe);
	}

	@Test(expected = AccountExpiredException.class)
	public void accountExpiredIsCorrectlyMapped() {
		this.provider.contextFactory = createContextFactoryThrowing(new AuthenticationException(msg + "701, xxxx]"));
		this.provider.setConvertSubErrorCodesToExceptions(true);
		this.provider.authenticate(this.joe);
	}

	@Test(expected = LockedException.class)
	public void accountLockedIsCorrectlyMapped() {
		this.provider.contextFactory = createContextFactoryThrowing(new AuthenticationException(msg + "775, xxxx]"));
		this.provider.setConvertSubErrorCodesToExceptions(true);
		this.provider.authenticate(this.joe);
	}

	@Test(expected = BadCredentialsException.class)
	public void unknownErrorCodeIsCorrectlyMapped() {
		this.provider.contextFactory = createContextFactoryThrowing(new AuthenticationException(msg + "999, xxxx]"));
		this.provider.setConvertSubErrorCodesToExceptions(true);
		this.provider.authenticate(this.joe);
	}

	@Test(expected = BadCredentialsException.class)
	public void errorWithNoSubcodeIsHandledCleanly() {
		this.provider.contextFactory = createContextFactoryThrowing(new AuthenticationException(msg));
		this.provider.setConvertSubErrorCodesToExceptions(true);
		this.provider.authenticate(this.joe);
	}

	@Test(expected = org.springframework.ldap.CommunicationException.class)
	public void nonAuthenticationExceptionIsConvertedToSpringLdapException() throws Throwable {
		try {
			this.provider.contextFactory = createContextFactoryThrowing(new CommunicationException(msg));
			this.provider.authenticate(this.joe);
		}
		catch (InternalAuthenticationServiceException ex) {
			// Since GH-8418 ldap communication exception is wrapped into
			// InternalAuthenticationServiceException.
			// This test is about the wrapped exception, so we throw it.
			throw ex.getCause();
		}
	}

	@Test(expected = org.springframework.security.authentication.InternalAuthenticationServiceException.class)
	public void connectionExceptionIsWrappedInInternalException() throws Exception {
		ActiveDirectoryLdapAuthenticationProvider noneReachableProvider = new ActiveDirectoryLdapAuthenticationProvider(
				"mydomain.eu", NON_EXISTING_LDAP_PROVIDER, "dc=ad,dc=eu,dc=mydomain");
		noneReachableProvider
				.setContextEnvironmentProperties(Collections.singletonMap("com.sun.jndi.ldap.connect.timeout", "5"));
		noneReachableProvider.doAuthentication(this.joe);
	}

	@Test
	public void rootDnProvidedSeparatelyFromDomainAlsoWorks() throws Exception {
		ActiveDirectoryLdapAuthenticationProvider provider = new ActiveDirectoryLdapAuthenticationProvider(
				"mydomain.eu", EXISTING_LDAP_PROVIDER, "dc=ad,dc=eu,dc=mydomain");
		checkAuthentication("dc=ad,dc=eu,dc=mydomain", provider);

	}

	@Test(expected = IllegalArgumentException.class)
	public void setContextEnvironmentPropertiesNull() {
		this.provider.setContextEnvironmentProperties(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void setContextEnvironmentPropertiesEmpty() {
		this.provider.setContextEnvironmentProperties(new Hashtable<>());
	}

	@Test
	public void contextEnvironmentPropertiesUsed() {
		Hashtable<String, Object> env = new Hashtable<>();

		env.put("java.naming.ldap.factory.socket", "unknown.package.NonExistingSocketFactory");
		this.provider.setContextEnvironmentProperties(env);

		try {
			this.provider.authenticate(this.joe);
			fail("CommunicationException was expected with a root cause of ClassNotFoundException");
		}
		catch (InternalAuthenticationServiceException expected) {
			assertThat(expected.getCause()).isInstanceOf(org.springframework.ldap.CommunicationException.class);
			org.springframework.ldap.CommunicationException cause = (org.springframework.ldap.CommunicationException) expected
					.getCause();
			assertThat(cause.getRootCause()).isInstanceOf(ClassNotFoundException.class);
		}
	}

	ContextFactory createContextFactoryThrowing(final NamingException ex) {
		return new ContextFactory() {
			@Override
			DirContext createContext(Hashtable<?, ?> env) throws NamingException {
				throw ex;
			}
		};
	}

	ContextFactory createContextFactoryReturning(final DirContext ctx) {
		return new ContextFactory() {
			@Override
			DirContext createContext(Hashtable<?, ?> env) {
				return ctx;
			}
		};
	}

	private void checkAuthentication(String rootDn, ActiveDirectoryLdapAuthenticationProvider provider)
			throws NamingException {
		DirContext ctx = mock(DirContext.class);
		given(ctx.getNameInNamespace()).willReturn("");

		DirContextAdapter dca = new DirContextAdapter();
		SearchResult sr = new SearchResult("CN=Joe Jannsen,CN=Users", dca, dca.getAttributes());
		@SuppressWarnings("deprecation")
		DistinguishedName searchBaseDn = new DistinguishedName(rootDn);
		given(ctx.search(eq(searchBaseDn), any(String.class), any(Object[].class), any(SearchControls.class)))
				.willReturn(new MockNamingEnumeration(sr)).willReturn(new MockNamingEnumeration(sr));

		provider.contextFactory = createContextFactoryReturning(ctx);

		Authentication result = provider.authenticate(this.joe);

		assertThat(result.getAuthorities()).isEmpty();

		dca.addAttributeValue("memberOf", "CN=Admin,CN=Users,DC=mydomain,DC=eu");

		result = provider.authenticate(this.joe);

		assertThat(result.getAuthorities()).hasSize(1);
	}

	static class MockNamingEnumeration implements NamingEnumeration<SearchResult> {

		private SearchResult sr;

		MockNamingEnumeration(SearchResult sr) {
			this.sr = sr;
		}

		@Override
		public SearchResult next() {
			SearchResult result = this.sr;
			this.sr = null;
			return result;
		}

		@Override
		public boolean hasMore() {
			return this.sr != null;
		}

		@Override
		public void close() {
		}

		@Override
		public boolean hasMoreElements() {
			return hasMore();
		}

		@Override
		public SearchResult nextElement() {
			return next();
		}

	}

}
