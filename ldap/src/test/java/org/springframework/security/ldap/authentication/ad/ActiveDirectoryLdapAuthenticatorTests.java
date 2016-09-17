/*
 * Copyright 2012-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.ldap.authentication.ad;

import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.ldap.AuthenticationException;
import org.springframework.ldap.NamingException;
import org.springframework.ldap.core.DirContextAdapter;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.support.BaseLdapPathContextSource;
import org.springframework.ldap.support.LdapUtils;
import org.springframework.security.authentication.*;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.ldap.authentication.AuthenticationPrincipalDecorator;
import org.springframework.security.ldap.search.FilterBasedLdapUserSearch;
import org.springframework.security.ldap.search.LdapUserSearch;

import javax.naming.Name;
import javax.naming.NamingEnumeration;
import javax.naming.directory.DirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.LdapName;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link ActiveDirectoryLdapAuthenticator}.
 *
 * @author Joe Grandja
 */
public class ActiveDirectoryLdapAuthenticatorTests {
	private static final String AD_ERROR_MESSAGE_PREFIX =
		"[LDAP: error code 49 - 80858585: LdapErr: DSID-DECAFF0, comment: AcceptSecurityContext error, data ";

	private static final String BASE_DN = "dc=springframework,dc=org";
	private static final String MANAGER_DN = "uid=manager@springframework.org," + BASE_DN;
	private static final String USER_DN = "uid=joe@springframework.org," + BASE_DN;
	private static final String DEFAULT_PASSWORD = "password";
	private static final String USER_DN_PATTERN = "uid={0}";
	private static final String SEARCH_FILTER = "uid={0}";
	private DirContext dirContext;
	private BaseLdapPathContextSource contextSource;
	private ActiveDirectoryLdapAuthenticator ldapAuthenticator;
	private UsernamePasswordAuthenticationToken authenticationToken;

	@Before
	public void setup() throws Exception {
		dirContext = mock(DirContext.class);
		contextSource = mock(BaseLdapPathContextSource.class);
		when(contextSource.getReadOnlyContext()).thenReturn(dirContext);
		when(contextSource.getReadWriteContext()).thenReturn(dirContext);
		LdapName baseDN = LdapUtils.newLdapName(BASE_DN);
		when(contextSource.getBaseLdapName()).thenReturn(baseDN);

		ldapAuthenticator = new ActiveDirectoryLdapAuthenticator(contextSource);
		authenticationToken = new UsernamePasswordAuthenticationToken("joe", DEFAULT_PASSWORD);

		// Set up default search result
		DirContextAdapter dirContextAdapter = new DirContextAdapter();
		dirContextAdapter.setDn(LdapUtils.newLdapName(USER_DN));
		dirContextAdapter.setAttributeValue("userPassword", DEFAULT_PASSWORD.getBytes());
		SearchResult searchResult = new SearchResult(USER_DN,
			dirContextAdapter, dirContextAdapter.getAttributes());
		when(dirContext.search(any(Name.class), anyString(), any(Object[].class), any(SearchControls.class)))
			.thenReturn(new MockNamingEnumeration(searchResult));
	}

	@Test(expected = IllegalArgumentException.class)
	public void afterPropertiesSetWhenNoPropertiesAreSetThenThrowIllegalArgumentException() throws Exception {
		ldapAuthenticator.afterPropertiesSet();
	}

	@Test
	public void afterPropertiesSetWhenMinimumPropertiesAreSetThenPass() throws Exception {
		ldapAuthenticator.setUserDnPatterns(new String[] {USER_DN_PATTERN});

		ldapAuthenticator.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void afterPropertiesSetWhenManagerPropertiesAreIncorrectlySetThenThrowIllegalArgumentException() throws Exception {
		ldapAuthenticator.setUserDnPatterns(new String[] {USER_DN_PATTERN});
		ldapAuthenticator.setManagerDn(MANAGER_DN);

		ldapAuthenticator.afterPropertiesSet();
	}

	@Test
	public void afterPropertiesSetWhenManagerPropertiesAreCorrectlySetThenPass() throws Exception {
		ldapAuthenticator.setUserDnPatterns(new String[] {USER_DN_PATTERN});
		ldapAuthenticator.setManagerDn(MANAGER_DN);
		ldapAuthenticator.setManagerPassword(DEFAULT_PASSWORD);
		ldapAuthenticator.setSearchFilter(SEARCH_FILTER);

		ldapAuthenticator.afterPropertiesSet();
	}

	@Test
	public void authenticateWhenUserDnPatternsIsSetThenBindAsUser() throws Exception {
		ldapAuthenticator.setUserDnPatterns(new String[] {USER_DN_PATTERN});

		ArgumentCaptor<String> bindPrincipalDnCaptor = ArgumentCaptor.forClass(String.class);
		when(contextSource.getContext(bindPrincipalDnCaptor.capture(), anyString())).thenReturn(dirContext);

		DirContextOperations result = ldapAuthenticator.authenticate(authenticationToken);

		assertThat(result).isNotNull();
		assertThat(bindPrincipalDnCaptor.getValue()).isEqualTo(USER_DN);
	}

	@Test
	public void authenticateWhenMultipleUserDnPatternsAreSetThenAttemptBindOnEach() throws Exception {
		// Setup 2 User DN Patterns to allow for 2 bind attempts
		ldapAuthenticator.setUserDnPatterns(new String[] {USER_DN_PATTERN, "username={0}"});

		ArgumentCaptor<String> bindPrincipalDnCaptor = ArgumentCaptor.forClass(String.class);
		// Throw exception on 1st bind attempt and pass through on 2nd attempt
		when(contextSource.getContext(bindPrincipalDnCaptor.capture(), anyString()))
			.thenThrow(new AuthenticationException()).thenReturn(dirContext);

		DirContextOperations result = ldapAuthenticator.authenticate(authenticationToken);

		assertThat(result).isNotNull();
		assertThat(bindPrincipalDnCaptor.getValue()).isEqualTo(USER_DN.replace("uid", "username"));
	}

	@Test
	public void authenticateWhenMultipleUserDnPatternsAndUserSearchAreSetThenAttemptBindOnEachAndSearch() throws Exception {
		// Setup 2 User DN Patterns and 1 User Search object to allow for 2 bind attempts and 1 search
		ldapAuthenticator.setUserDnPatterns(new String[] {USER_DN_PATTERN, "username={0}"});
		LdapUserSearch userSearch = new FilterBasedLdapUserSearch("", SEARCH_FILTER, contextSource);
		ldapAuthenticator.setUserSearch(userSearch);

		// Throw exception on 1st and 2nd bind attempts allowing the search to execute
		when(contextSource.getContext(anyString(), anyString()))
			.thenThrow(new AuthenticationException()).thenThrow(new AuthenticationException());

		DirContextOperations result = ldapAuthenticator.authenticate(authenticationToken);

		assertThat(result).isNotNull();
		assertThat(result.getNameInNamespace()).isEqualTo(USER_DN);
	}

	@Test
	public void authenticateWhenUserSearchIsSetThenUserFound() throws Exception {
		LdapUserSearch userSearch = new FilterBasedLdapUserSearch("", SEARCH_FILTER, contextSource);
		ldapAuthenticator.setUserSearch(userSearch);

		DirContextOperations result = ldapAuthenticator.authenticate(authenticationToken);

		assertThat(result).isNotNull();
		assertThat(result.getNameInNamespace()).isEqualTo(USER_DN);
	}

	@Test(expected = BadCredentialsException.class)
	public void authenticateWhenNonBindingUserDnPatternsAreSetThenThrowBadCredentials() throws Exception {
		// Setup 2 User DN Patterns to allow for 2 bind attempts
		ldapAuthenticator.setUserDnPatterns(new String[] {USER_DN_PATTERN, "username={0}"});

		when(contextSource.getContext(anyString(), anyString()))
			.thenThrow(new AuthenticationException()).thenThrow(new AuthenticationException());;

		DirContextOperations result = ldapAuthenticator.authenticate(authenticationToken);
	}

	@Test(expected = UsernameNotFoundException.class)
	public void authenticateWhenNonFindingUserSearchIsSetThenThrowUsernameNotFoundException() throws Exception {
		LdapUserSearch userSearch = new FilterBasedLdapUserSearch("", SEARCH_FILTER, contextSource);
		ldapAuthenticator.setUserSearch(userSearch);

		when(dirContext.search(any(Name.class), anyString(), any(Object[].class), any(SearchControls.class)))
			.thenThrow(new UsernameNotFoundException(""));

		DirContextOperations result = ldapAuthenticator.authenticate(authenticationToken);
	}

	@Test
	public void authenticateWhenManagerPropertiesAreSetThenBindAsManager() throws Exception {
		ldapAuthenticator.setManagerDn(MANAGER_DN);
		ldapAuthenticator.setManagerPassword(DEFAULT_PASSWORD);
		ldapAuthenticator.setSearchFilter(SEARCH_FILTER);

		ArgumentCaptor<String> bindPrincipalDnCaptor = ArgumentCaptor.forClass(String.class);
		when(contextSource.getContext(bindPrincipalDnCaptor.capture(), anyString())).thenReturn(dirContext);

		DirContextOperations result = ldapAuthenticator.authenticate(authenticationToken);

		assertThat(result).isNotNull();
		assertThat(bindPrincipalDnCaptor.getValue()).isEqualTo(MANAGER_DN);
	}

	@Test(expected = NamingException.class)
	public void authenticateWhenNonBindingManagerDnIsSetThenThrowNamingException() throws Exception {
		ldapAuthenticator.setManagerDn(MANAGER_DN);
		ldapAuthenticator.setManagerPassword(DEFAULT_PASSWORD);
		ldapAuthenticator.setSearchFilter(SEARCH_FILTER);

		when(contextSource.getContext(anyString(), anyString())).thenThrow(new AuthenticationException());

		DirContextOperations result = ldapAuthenticator.authenticate(authenticationToken);
	}

	@Test(expected = UsernameNotFoundException.class)
	public void authenticateWhenBindAsManagerAndNonFindingSearchFilterIsSetThenThrowUsernameNotFoundException() throws Exception {
		LdapUserSearch userSearch = new FilterBasedLdapUserSearch("", SEARCH_FILTER, contextSource);
		ldapAuthenticator.setManagerDn(MANAGER_DN);
		ldapAuthenticator.setManagerPassword(DEFAULT_PASSWORD);
		ldapAuthenticator.setSearchFilter(SEARCH_FILTER);

		when(contextSource.getContext(anyString(), anyString())).thenReturn(dirContext);

		IncorrectResultSizeDataAccessException incorrectResults = new IncorrectResultSizeDataAccessException(1, 0);
		when(dirContext.search(any(Name.class), anyString(), any(Object[].class), any(SearchControls.class)))
			.thenThrow(incorrectResults);

		DirContextOperations result = ldapAuthenticator.authenticate(authenticationToken);
	}

	@Test(expected = BadCredentialsException.class)
	public void authenticateWhenBindAsManagerAndMultipleFindingSearchFilterIsSetThenThrowBadCredentialsException() throws Exception {
		LdapUserSearch userSearch = new FilterBasedLdapUserSearch("", SEARCH_FILTER, contextSource);
		ldapAuthenticator.setManagerDn(MANAGER_DN);
		ldapAuthenticator.setManagerPassword(DEFAULT_PASSWORD);
		ldapAuthenticator.setSearchFilter(SEARCH_FILTER);

		when(contextSource.getContext(anyString(), anyString())).thenReturn(dirContext);

		IncorrectResultSizeDataAccessException incorrectResults = new IncorrectResultSizeDataAccessException(1, 2);
		when(dirContext.search(any(Name.class), anyString(), any(Object[].class), any(SearchControls.class)))
			.thenThrow(incorrectResults);

		DirContextOperations result = ldapAuthenticator.authenticate(authenticationToken);
	}

	@Test(expected = BadCredentialsException.class)
	public void authenticateWhenBindAsManagerAndUserCredentialsAreInvalidThenThrowBadCredentialsException() throws Exception {
		LdapUserSearch userSearch = new FilterBasedLdapUserSearch("", SEARCH_FILTER, contextSource);
		ldapAuthenticator.setManagerDn(MANAGER_DN);
		ldapAuthenticator.setManagerPassword(DEFAULT_PASSWORD);
		ldapAuthenticator.setSearchFilter(SEARCH_FILTER);

		when(contextSource.getContext(anyString(), anyString())).thenReturn(dirContext);

		UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken("joe", DEFAULT_PASSWORD + "-invalid");
		DirContextOperations result = ldapAuthenticator.authenticate(authenticationToken);
	}

	@Test
	public void authenticateWhenDefaultAuthenticationPrincipalDecoratorIsSetThenBaseDnAppendedToPrincipal() throws Exception {
		ldapAuthenticator.setUserDnPatterns(new String[] {USER_DN_PATTERN});

		ArgumentCaptor<String> bindPrincipalDnCaptor = ArgumentCaptor.forClass(String.class);
		when(contextSource.getContext(bindPrincipalDnCaptor.capture(), anyString())).thenReturn(dirContext);

		DirContextOperations result = ldapAuthenticator.authenticate(authenticationToken);

		assertThat(result).isNotNull();
		assertThat(bindPrincipalDnCaptor.getValue()).contains("uid=joe@springframework.org,");
	}

	@Test
	public void authenticateWhenNoOpAuthenticationPrincipalDecoratorIsSetThenPrincipalIsUnchanged() throws Exception {
		ldapAuthenticator.setUserDnPatterns(new String[] {USER_DN_PATTERN});
		ldapAuthenticator.setAuthenticationPrincipalDecorator(new AuthenticationPrincipalDecorator() {
			@Override
			public String decorate(String principal) {
				return principal;
			}
		});

		ArgumentCaptor<String> bindPrincipalDnCaptor = ArgumentCaptor.forClass(String.class);
		when(contextSource.getContext(bindPrincipalDnCaptor.capture(), anyString())).thenReturn(dirContext);

		DirContextOperations result = ldapAuthenticator.authenticate(authenticationToken);

		assertThat(result).isNotNull();
		assertThat(bindPrincipalDnCaptor.getValue()).contains("uid=joe,");
	}

	@Test(expected = BadCredentialsException.class)
	public void authenticateWhenConvertSubErrorCodeToExceptionTrueAndSubErrorCodeUserNotFoundThenThrowBadCredentialsException() {
		ldapAuthenticator.setUserDnPatterns(new String[] {USER_DN_PATTERN});
		ldapAuthenticator.setConvertSubErrorCodeToException(true);

		AuthenticationException authenticationException =
			new AuthenticationException(new javax.naming.AuthenticationException(AD_ERROR_MESSAGE_PREFIX + "525, xxxx]"));

		when(contextSource.getContext(anyString(), anyString())).thenThrow(authenticationException);

		DirContextOperations result = ldapAuthenticator.authenticate(authenticationToken);
	}

	@Test(expected = BadCredentialsException.class)
	public void authenticateWhenConvertSubErrorCodeToExceptionTrueAndSubErrorCodeIncorrectPasswordThenThrowBadCredentialsException() {
		ldapAuthenticator.setUserDnPatterns(new String[] {USER_DN_PATTERN});
		ldapAuthenticator.setConvertSubErrorCodeToException(true);

		AuthenticationException authenticationException =
			new AuthenticationException(new javax.naming.AuthenticationException(AD_ERROR_MESSAGE_PREFIX + "52e, xxxx]"));

		when(contextSource.getContext(anyString(), anyString())).thenThrow(authenticationException);

		DirContextOperations result = ldapAuthenticator.authenticate(authenticationToken);
	}

	@Test(expected = BadCredentialsException.class)
	public void authenticateWhenConvertSubErrorCodeToExceptionTrueAndSubErrorCodeNotPermittedThenThrowBadCredentialsException() {
		ldapAuthenticator.setUserDnPatterns(new String[] {USER_DN_PATTERN});
		ldapAuthenticator.setConvertSubErrorCodeToException(true);

		AuthenticationException authenticationException =
			new AuthenticationException(new javax.naming.AuthenticationException(AD_ERROR_MESSAGE_PREFIX + "530, xxxx]"));

		when(contextSource.getContext(anyString(), anyString())).thenThrow(authenticationException);

		DirContextOperations result = ldapAuthenticator.authenticate(authenticationToken);
	}

	@Test(expected = BadCredentialsException.class)
	public void authenticateWhenConvertSubErrorCodeToExceptionTrueAndSubErrorCodePasswordNeedsResetThenThrowBadCredentialsException() {
		ldapAuthenticator.setUserDnPatterns(new String[] {USER_DN_PATTERN});
		ldapAuthenticator.setConvertSubErrorCodeToException(true);

		AuthenticationException authenticationException =
			new AuthenticationException(new javax.naming.AuthenticationException(AD_ERROR_MESSAGE_PREFIX + "773, xxxx]"));

		when(contextSource.getContext(anyString(), anyString())).thenThrow(authenticationException);

		DirContextOperations result = ldapAuthenticator.authenticate(authenticationToken);
	}

	@Test(expected = CredentialsExpiredException.class)
	public void authenticateWhenConvertSubErrorCodeToExceptionTrueAndSubErrorCodeExpiredPasswordThenThrowCredentialsExpiredException() {
		ldapAuthenticator.setUserDnPatterns(new String[] {USER_DN_PATTERN});
		ldapAuthenticator.setConvertSubErrorCodeToException(true);

		AuthenticationException authenticationException =
			new AuthenticationException(new javax.naming.AuthenticationException(AD_ERROR_MESSAGE_PREFIX + "532, xxxx]"));

		when(contextSource.getContext(anyString(), anyString())).thenThrow(authenticationException);

		DirContextOperations result = ldapAuthenticator.authenticate(authenticationToken);
	}

	@Test(expected = DisabledException.class)
	public void authenticateWhenConvertSubErrorCodeToExceptionTrueAndSubErrorCodeAccountDisabledThenThrowDisabledException() {
		ldapAuthenticator.setUserDnPatterns(new String[] {USER_DN_PATTERN});
		ldapAuthenticator.setConvertSubErrorCodeToException(true);

		AuthenticationException authenticationException =
			new AuthenticationException(new javax.naming.AuthenticationException(AD_ERROR_MESSAGE_PREFIX + "533, xxxx]"));

		when(contextSource.getContext(anyString(), anyString())).thenThrow(authenticationException);

		DirContextOperations result = ldapAuthenticator.authenticate(authenticationToken);
	}

	@Test(expected = AccountExpiredException.class)
	public void authenticateWhenConvertSubErrorCodeToExceptionTrueAndSubErrorCodeAccountExpiredThenThrowAccountExpiredException() {
		ldapAuthenticator.setUserDnPatterns(new String[] {USER_DN_PATTERN});
		ldapAuthenticator.setConvertSubErrorCodeToException(true);

		AuthenticationException authenticationException =
			new AuthenticationException(new javax.naming.AuthenticationException(AD_ERROR_MESSAGE_PREFIX + "701, xxxx]"));

		when(contextSource.getContext(anyString(), anyString())).thenThrow(authenticationException);

		DirContextOperations result = ldapAuthenticator.authenticate(authenticationToken);
	}

	@Test(expected = LockedException.class)
	public void authenticateWhenConvertSubErrorCodeToExceptionTrueAndSubErrorCodeAccountLockedThenThrowLockedException() {
		ldapAuthenticator.setUserDnPatterns(new String[] {USER_DN_PATTERN});
		ldapAuthenticator.setConvertSubErrorCodeToException(true);

		AuthenticationException authenticationException =
			new AuthenticationException(new javax.naming.AuthenticationException(AD_ERROR_MESSAGE_PREFIX + "775, xxxx]"));

		when(contextSource.getContext(anyString(), anyString())).thenThrow(authenticationException);

		DirContextOperations result = ldapAuthenticator.authenticate(authenticationToken);
	}

	@Test(expected = BadCredentialsException.class)
	public void authenticateWhenConvertSubErrorCodeToExceptionTrueAndSubErrorCodeUnknownThenThrowBadCredentialsException() {
		ldapAuthenticator.setUserDnPatterns(new String[] {USER_DN_PATTERN});
		ldapAuthenticator.setConvertSubErrorCodeToException(true);

		AuthenticationException authenticationException =
			new AuthenticationException(new javax.naming.AuthenticationException(AD_ERROR_MESSAGE_PREFIX + "999, xxxx]"));

		when(contextSource.getContext(anyString(), anyString())).thenThrow(authenticationException);

		DirContextOperations result = ldapAuthenticator.authenticate(authenticationToken);
	}

	@Test(expected = BadCredentialsException.class)
	public void authenticateWhenConvertSubErrorCodeToExceptionTrueAndSubErrorCodeEmptyThenThrowBadCredentialsException() {
		ldapAuthenticator.setUserDnPatterns(new String[] {USER_DN_PATTERN});
		ldapAuthenticator.setConvertSubErrorCodeToException(true);

		AuthenticationException authenticationException =
			new AuthenticationException(new javax.naming.AuthenticationException(AD_ERROR_MESSAGE_PREFIX));

		when(contextSource.getContext(anyString(), anyString())).thenThrow(authenticationException);

		DirContextOperations result = ldapAuthenticator.authenticate(authenticationToken);
	}

	private static class MockNamingEnumeration implements NamingEnumeration<SearchResult> {
		private SearchResult result;

		private MockNamingEnumeration(SearchResult result) {
			this.result = result;
		}

		public SearchResult next() {
			SearchResult result = this.result;
			this.result = null;
			return result;
		}

		public boolean hasMore() {
			return result != null;
		}

		public void close() {
		}

		public boolean hasMoreElements() {
			return hasMore();
		}

		public SearchResult nextElement() {
			return next();
		}
	}
}
