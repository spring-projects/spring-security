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

package org.springframework.security.web.authentication.www;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import java.io.IOException;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.util.StringUtils;

/**
 * Tests {@link DigestAuthenticationFilter}.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public class DigestAuthenticationFilterTests {
	// ~ Static fields/initializers
	// =====================================================================================

	private static final String NC = "00000002";

	private static final String CNONCE = "c822c727a648aba7";

	private static final String REALM = "The Actual, Correct Realm Name";

	private static final String KEY = "springsecurity";

	private static final String QOP = "auth";

	private static final String USERNAME = "rod,ok";

	private static final String PASSWORD = "koala";

	private static final String REQUEST_URI = "/some_file.html";

	/**
	 * A standard valid nonce with a validity period of 60 seconds
	 */
	private static final String NONCE = generateNonce(60);

	// ~ Instance fields
	// ================================================================================================

	// private ApplicationContext ctx;
	private DigestAuthenticationFilter filter;

	private MockHttpServletRequest request;

	// ~ Methods
	// ========================================================================================================

	private String createAuthorizationHeader(String username, String realm, String nonce,
			String uri, String responseDigest, String qop, String nc, String cnonce) {
		return "Digest username=\"" + username + "\", realm=\"" + realm + "\", nonce=\""
				+ nonce + "\", uri=\"" + uri + "\", response=\"" + responseDigest
				+ "\", qop=" + qop + ", nc=" + nc + ", cnonce=\"" + cnonce + "\"";
	}

	private MockHttpServletResponse executeFilterInContainerSimulator(Filter filter,
			final ServletRequest request, final boolean expectChainToProceed)
					throws ServletException, IOException {
		final MockHttpServletResponse response = new MockHttpServletResponse();

		final FilterChain chain = mock(FilterChain.class);

		filter.doFilter(request, response, chain);

		verify(chain, times(expectChainToProceed ? 1 : 0)).doFilter(request, response);
		return response;
	}

	private static String generateNonce(int validitySeconds) {
		long expiryTime = System.currentTimeMillis() + (validitySeconds * 1000);
		String signatureValue = DigestUtils.md5Hex(expiryTime + ":" + KEY);
		String nonceValue = expiryTime + ":" + signatureValue;

		return new String(Base64.encodeBase64(nonceValue.getBytes()));
	}

	@After
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Before
	public void setUp() {
		SecurityContextHolder.clearContext();

		// Create User Details Service
		UserDetailsService uds = new UserDetailsService() {

			public UserDetails loadUserByUsername(String username)
					throws UsernameNotFoundException {
				return new User("rod,ok", "koala",
						AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"));
			}
		};

		DigestAuthenticationEntryPoint ep = new DigestAuthenticationEntryPoint();
		ep.setRealmName(REALM);
		ep.setKey(KEY);

		filter = new DigestAuthenticationFilter();
		filter.setUserDetailsService(uds);
		filter.setAuthenticationEntryPoint(ep);

		request = new MockHttpServletRequest("GET", REQUEST_URI);
		request.setServletPath(REQUEST_URI);
	}

	@Test
	public void testExpiredNonceReturnsForbiddenWithStaleHeader() throws Exception {
		String nonce = generateNonce(0);
		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM,
				PASSWORD, "GET", REQUEST_URI, QOP, nonce, NC, CNONCE);

		request.addHeader("Authorization", createAuthorizationHeader(USERNAME, REALM,
				nonce, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

		Thread.sleep(1000); // ensures token expired

		MockHttpServletResponse response = executeFilterInContainerSimulator(filter,
				request, false);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);

		String header = response.getHeader("WWW-Authenticate").toString().substring(7);
		String[] headerEntries = StringUtils.commaDelimitedListToStringArray(header);
		Map<String, String> headerMap = DigestAuthUtils.splitEachArrayElementAndCreateMap(
				headerEntries, "=", "\"");
		assertThat(headerMap.get("stale")).isEqualTo("true");
	}

	@Test
	public void testFilterIgnoresRequestsContainingNoAuthorizationHeader()
			throws Exception {
		executeFilterInContainerSimulator(filter, request, true);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void testGettersSetters() {
		DigestAuthenticationFilter filter = new DigestAuthenticationFilter();
		filter.setUserDetailsService(mock(UserDetailsService.class));
		assertThat(filter.getUserDetailsService() != null).isTrue();

		filter.setAuthenticationEntryPoint(new DigestAuthenticationEntryPoint());
		assertThat(filter.getAuthenticationEntryPoint() != null).isTrue();

		filter.setUserCache(null);
		assertThat(filter.getUserCache()).isNull();
		filter.setUserCache(new NullUserCache());
		assertThat(filter.getUserCache()).isNotNull();
	}

	@Test
	public void testInvalidDigestAuthorizationTokenGeneratesError() throws Exception {
		String token = "NOT_A_VALID_TOKEN_AS_MISSING_COLON";

		request.addHeader("Authorization",
				"Digest " + new String(Base64.encodeBase64(token.getBytes())));

		MockHttpServletResponse response = executeFilterInContainerSimulator(filter,
				request, false);

		assertThat(response.getStatus()).isEqualTo(401);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void testMalformedHeaderReturnsForbidden() throws Exception {
		request.addHeader("Authorization", "Digest scsdcsdc");

		MockHttpServletResponse response = executeFilterInContainerSimulator(filter,
				request, false);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void testNonBase64EncodedNonceReturnsForbidden() throws Exception {
		String nonce = "NOT_BASE_64_ENCODED";

		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM,
				PASSWORD, "GET", REQUEST_URI, QOP, nonce, NC, CNONCE);

		request.addHeader("Authorization", createAuthorizationHeader(USERNAME, REALM,
				nonce, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

		MockHttpServletResponse response = executeFilterInContainerSimulator(filter,
				request, false);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void testNonceWithIncorrectSignatureForNumericFieldReturnsForbidden()
			throws Exception {
		String nonce = new String(
				Base64.encodeBase64("123456:incorrectStringPassword".getBytes()));
		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM,
				PASSWORD, "GET", REQUEST_URI, QOP, nonce, NC, CNONCE);

		request.addHeader("Authorization", createAuthorizationHeader(USERNAME, REALM,
				nonce, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

		MockHttpServletResponse response = executeFilterInContainerSimulator(filter,
				request, false);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void testNonceWithNonNumericFirstElementReturnsForbidden() throws Exception {
		String nonce = new String(
				Base64.encodeBase64("hello:ignoredSecondElement".getBytes()));
		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM,
				PASSWORD, "GET", REQUEST_URI, QOP, nonce, NC, CNONCE);

		request.addHeader("Authorization", createAuthorizationHeader(USERNAME, REALM,
				nonce, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

		MockHttpServletResponse response = executeFilterInContainerSimulator(filter,
				request, false);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void testNonceWithoutTwoColonSeparatedElementsReturnsForbidden()
			throws Exception {
		String nonce = new String(
				Base64.encodeBase64("a base 64 string without a colon".getBytes()));
		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM,
				PASSWORD, "GET", REQUEST_URI, QOP, nonce, NC, CNONCE);

		request.addHeader("Authorization", createAuthorizationHeader(USERNAME, REALM,
				nonce, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

		MockHttpServletResponse response = executeFilterInContainerSimulator(filter,
				request, false);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void testNormalOperationWhenPasswordIsAlreadyEncoded() throws Exception {
		String encodedPassword = DigestAuthUtils.encodePasswordInA1Format(USERNAME, REALM,
				PASSWORD);
		String responseDigest = DigestAuthUtils.generateDigest(true, USERNAME, REALM,
				encodedPassword, "GET", REQUEST_URI, QOP, NONCE, NC, CNONCE);

		request.addHeader("Authorization", createAuthorizationHeader(USERNAME, REALM,
				NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

		executeFilterInContainerSimulator(filter, request, true);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(
				((UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUsername()).isEqualTo(
						USERNAME);
	}

	@Test
	public void testNormalOperationWhenPasswordNotAlreadyEncoded() throws Exception {
		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM,
				PASSWORD, "GET", REQUEST_URI, QOP, NONCE, NC, CNONCE);

		request.addHeader("Authorization", createAuthorizationHeader(USERNAME, REALM,
				NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

		executeFilterInContainerSimulator(filter, request, true);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(
				((UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUsername()).isEqualTo(
						USERNAME);
		assertThat(
				SecurityContextHolder.getContext().getAuthentication().isAuthenticated()).isFalse();
	}

	@Test
	public void testNormalOperationWhenPasswordNotAlreadyEncodedAndWithoutReAuthentication()
			throws Exception {
		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM,
				PASSWORD, "GET", REQUEST_URI, QOP, NONCE, NC, CNONCE);

		request.addHeader("Authorization", createAuthorizationHeader(USERNAME, REALM,
				NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

		filter.setCreateAuthenticatedToken(true);
		executeFilterInContainerSimulator(filter, request, true);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(
				((UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUsername()).isEqualTo(
						USERNAME);
		assertThat(
				SecurityContextHolder.getContext().getAuthentication().isAuthenticated()).isTrue();
		assertThat(
				SecurityContextHolder.getContext().getAuthentication().getAuthorities()).isEqualTo(
						AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"));
	}

	@Test
	public void otherAuthorizationSchemeIsIgnored() throws Exception {
		request.addHeader("Authorization", "SOME_OTHER_AUTHENTICATION_SCHEME");

		executeFilterInContainerSimulator(filter, request, true);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test(expected = IllegalArgumentException.class)
	public void startupDetectsMissingAuthenticationEntryPoint() throws Exception {
		DigestAuthenticationFilter filter = new DigestAuthenticationFilter();
		filter.setUserDetailsService(mock(UserDetailsService.class));
		filter.afterPropertiesSet();
	}

	@Test(expected = IllegalArgumentException.class)
	public void startupDetectsMissingUserDetailsService() throws Exception {
		DigestAuthenticationFilter filter = new DigestAuthenticationFilter();
		filter.setAuthenticationEntryPoint(new DigestAuthenticationEntryPoint());
		filter.afterPropertiesSet();
	}

	@Test
	public void successfulLoginThenFailedLoginResultsInSessionLosingToken()
			throws Exception {
		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM,
				PASSWORD, "GET", REQUEST_URI, QOP, NONCE, NC, CNONCE);

		request.addHeader("Authorization", createAuthorizationHeader(USERNAME, REALM,
				NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

		executeFilterInContainerSimulator(filter, request, true);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();

		// Now retry, giving an invalid nonce
		responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM,
				"WRONG_PASSWORD", "GET", REQUEST_URI, QOP, NONCE, NC, CNONCE);

		request = new MockHttpServletRequest();
		request.addHeader("Authorization", createAuthorizationHeader(USERNAME, REALM,
				NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

		MockHttpServletResponse response = executeFilterInContainerSimulator(filter,
				request, false);

		// Check we lost our previous authentication
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void wrongCnonceBasedOnDigestReturnsForbidden() throws Exception {
		String cnonce = "NOT_SAME_AS_USED_FOR_DIGEST_COMPUTATION";

		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM,
				PASSWORD, "GET", REQUEST_URI, QOP, NONCE, NC, "DIFFERENT_CNONCE");

		request.addHeader("Authorization", createAuthorizationHeader(USERNAME, REALM,
				NONCE, REQUEST_URI, responseDigest, QOP, NC, cnonce));

		MockHttpServletResponse response = executeFilterInContainerSimulator(filter,
				request, false);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void wrongDigestReturnsForbidden() throws Exception {
		String password = "WRONG_PASSWORD";
		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM,
				password, "GET", REQUEST_URI, QOP, NONCE, NC, CNONCE);

		request.addHeader("Authorization", createAuthorizationHeader(USERNAME, REALM,
				NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

		MockHttpServletResponse response = executeFilterInContainerSimulator(filter,
				request, false);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void wrongRealmReturnsForbidden() throws Exception {
		String realm = "WRONG_REALM";
		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, realm,
				PASSWORD, "GET", REQUEST_URI, QOP, NONCE, NC, CNONCE);

		request.addHeader("Authorization", createAuthorizationHeader(USERNAME, realm,
				NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

		MockHttpServletResponse response = executeFilterInContainerSimulator(filter,
				request, false);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void wrongUsernameReturnsForbidden() throws Exception {
		String responseDigest = DigestAuthUtils.generateDigest(false, "NOT_A_KNOWN_USER",
				REALM, PASSWORD, "GET", REQUEST_URI, QOP, NONCE, NC, CNONCE);

		request.addHeader("Authorization", createAuthorizationHeader(USERNAME, REALM,
				NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

		MockHttpServletResponse response = executeFilterInContainerSimulator(filter,
				request, false);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	// SEC-3108
	@Test
	public void authenticationCreatesEmptyContext() throws Exception {
		SecurityContext existingContext = SecurityContextHolder.createEmptyContext();
		TestingAuthenticationToken existingAuthentication = new TestingAuthenticationToken(
				"existingauthenitcated", "pass", "ROLE_USER");
		existingContext.setAuthentication(existingAuthentication);

		SecurityContextHolder.setContext(existingContext);

		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM,
				PASSWORD, "GET", REQUEST_URI, QOP, NONCE, NC, CNONCE);

		request.addHeader("Authorization", createAuthorizationHeader(USERNAME, REALM,
				NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));

		filter.setCreateAuthenticatedToken(true);
		executeFilterInContainerSimulator(filter, request, true);

		assertThat(existingAuthentication).isSameAs(existingContext.getAuthentication());
	}
}
