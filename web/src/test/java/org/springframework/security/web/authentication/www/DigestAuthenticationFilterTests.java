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

import java.io.IOException;
import java.util.Map;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.MockSecurityContextHolderStrategy;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.cache.NullUserCache;
import org.springframework.security.test.web.CodecTestUtils;
import org.springframework.security.web.context.RequestAttributeSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.util.StringUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Tests {@link DigestAuthenticationFilter}.
 *
 * @author Ben Alex
 * @author Luke Taylor
 */
public class DigestAuthenticationFilterTests {

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

	// private ApplicationContext ctx;
	private DigestAuthenticationFilter filter;

	private MockHttpServletRequest request;

	private String createAuthorizationHeader(String username, String realm, String nonce, String uri,
			String responseDigest, String qop, String nc, String cnonce) {
		return "Digest username=\"" + username + "\", realm=\"" + realm + "\", nonce=\"" + nonce + "\", uri=\"" + uri
				+ "\", response=\"" + responseDigest + "\", qop=" + qop + ", nc=" + nc + ", cnonce=\"" + cnonce + "\"";
	}

	private MockHttpServletResponse executeFilterInContainerSimulator(Filter filter, final ServletRequest request,
			final boolean expectChainToProceed) throws ServletException, IOException {
		final MockHttpServletResponse response = new MockHttpServletResponse();
		final FilterChain chain = mock(FilterChain.class);
		filter.doFilter(request, response, chain);
		verify(chain, times(expectChainToProceed ? 1 : 0)).doFilter(request, response);
		return response;
	}

	private static String generateNonce(int validitySeconds) {
		return generateNonce(validitySeconds, KEY);
	}

	private static String generateNonce(int validitySeconds, String key) {
		long expiryTime = System.currentTimeMillis() + (validitySeconds * 1000);
		String signatureValue = CodecTestUtils.md5Hex(expiryTime + ":" + key);
		String nonceValue = expiryTime + ":" + signatureValue;
		return CodecTestUtils.encodeBase64(nonceValue);
	}

	@AfterEach
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@BeforeEach
	public void setUp() {
		SecurityContextHolder.clearContext();
		// Create User Details Service
		UserDetailsService uds = (username) -> new User("rod,ok", "koala",
				AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"));
		DigestAuthenticationEntryPoint ep = new DigestAuthenticationEntryPoint();
		ep.setRealmName(REALM);
		ep.setKey(KEY);
		this.filter = new DigestAuthenticationFilter();
		this.filter.setUserDetailsService(uds);
		this.filter.setAuthenticationEntryPoint(ep);
		this.request = new MockHttpServletRequest("GET", REQUEST_URI);
		this.request.setServletPath(REQUEST_URI);
	}

	@Test
	public void testExpiredNonceReturnsForbiddenWithStaleHeader() throws Exception {
		String nonce = generateNonce(0);
		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, PASSWORD, "GET", REQUEST_URI,
				QOP, nonce, NC, CNONCE);
		this.request.addHeader("Authorization",
				createAuthorizationHeader(USERNAME, REALM, nonce, REQUEST_URI, responseDigest, QOP, NC, CNONCE));
		Thread.sleep(1000); // ensures token expired
		MockHttpServletResponse response = executeFilterInContainerSimulator(this.filter, this.request, false);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
		String header = response.getHeader("WWW-Authenticate").toString().substring(7);
		String[] headerEntries = StringUtils.commaDelimitedListToStringArray(header);
		Map<String, String> headerMap = DigestAuthUtils.splitEachArrayElementAndCreateMap(headerEntries, "=", "\"");
		assertThat(headerMap.get("stale")).isEqualTo("true");
	}

	@Test
	public void doFilterWhenNonceHasBadKeyThenGeneratesError() throws Exception {
		String badNonce = generateNonce(60, "badkey");
		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, PASSWORD, "GET", REQUEST_URI,
				QOP, badNonce, NC, CNONCE);
		this.request.addHeader("Authorization",
				createAuthorizationHeader(USERNAME, REALM, badNonce, REQUEST_URI, responseDigest, QOP, NC, CNONCE));
		MockHttpServletResponse response = executeFilterInContainerSimulator(this.filter, this.request, false);
		assertThat(response.getStatus()).isEqualTo(401);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void testFilterIgnoresRequestsContainingNoAuthorizationHeader() throws Exception {
		executeFilterInContainerSimulator(this.filter, this.request, true);
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
		this.request.addHeader("Authorization", "Digest " + CodecTestUtils.encodeBase64(token));
		MockHttpServletResponse response = executeFilterInContainerSimulator(this.filter, this.request, false);
		assertThat(response.getStatus()).isEqualTo(401);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void testMalformedHeaderReturnsForbidden() throws Exception {
		this.request.addHeader("Authorization", "Digest scsdcsdc");
		MockHttpServletResponse response = executeFilterInContainerSimulator(this.filter, this.request, false);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void testNonBase64EncodedNonceReturnsForbidden() throws Exception {
		String nonce = "NOT_BASE_64_ENCODED";
		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, PASSWORD, "GET", REQUEST_URI,
				QOP, nonce, NC, CNONCE);
		this.request.addHeader("Authorization",
				createAuthorizationHeader(USERNAME, REALM, nonce, REQUEST_URI, responseDigest, QOP, NC, CNONCE));
		MockHttpServletResponse response = executeFilterInContainerSimulator(this.filter, this.request, false);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void testNonceWithIncorrectSignatureForNumericFieldReturnsForbidden() throws Exception {
		String nonce = CodecTestUtils.encodeBase64("123456:incorrectStringPassword");
		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, PASSWORD, "GET", REQUEST_URI,
				QOP, nonce, NC, CNONCE);
		this.request.addHeader("Authorization",
				createAuthorizationHeader(USERNAME, REALM, nonce, REQUEST_URI, responseDigest, QOP, NC, CNONCE));
		MockHttpServletResponse response = executeFilterInContainerSimulator(this.filter, this.request, false);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void testNonceWithNonNumericFirstElementReturnsForbidden() throws Exception {
		String nonce = CodecTestUtils.encodeBase64("hello:ignoredSecondElement");
		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, PASSWORD, "GET", REQUEST_URI,
				QOP, nonce, NC, CNONCE);
		this.request.addHeader("Authorization",
				createAuthorizationHeader(USERNAME, REALM, nonce, REQUEST_URI, responseDigest, QOP, NC, CNONCE));
		MockHttpServletResponse response = executeFilterInContainerSimulator(this.filter, this.request, false);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void testNonceWithoutTwoColonSeparatedElementsReturnsForbidden() throws Exception {
		String nonce = CodecTestUtils.encodeBase64("a base 64 string without a colon");
		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, PASSWORD, "GET", REQUEST_URI,
				QOP, nonce, NC, CNONCE);
		this.request.addHeader("Authorization",
				createAuthorizationHeader(USERNAME, REALM, nonce, REQUEST_URI, responseDigest, QOP, NC, CNONCE));
		MockHttpServletResponse response = executeFilterInContainerSimulator(this.filter, this.request, false);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void testNormalOperationWhenPasswordIsAlreadyEncoded() throws Exception {
		String encodedPassword = DigestAuthUtils.encodePasswordInA1Format(USERNAME, REALM, PASSWORD);
		String responseDigest = DigestAuthUtils.generateDigest(true, USERNAME, REALM, encodedPassword, "GET",
				REQUEST_URI, QOP, NONCE, NC, CNONCE);
		this.request.addHeader("Authorization",
				createAuthorizationHeader(USERNAME, REALM, NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));
		executeFilterInContainerSimulator(this.filter, this.request, true);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(((UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUsername())
				.isEqualTo(USERNAME);
		assertThat(this.request.getAttribute(RequestAttributeSecurityContextRepository.DEFAULT_REQUEST_ATTR_NAME))
				.isNotNull();
	}

	@Test
	public void testNormalOperationWhenPasswordNotAlreadyEncoded() throws Exception {
		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, PASSWORD, "GET", REQUEST_URI,
				QOP, NONCE, NC, CNONCE);
		this.request.addHeader("Authorization",
				createAuthorizationHeader(USERNAME, REALM, NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));
		executeFilterInContainerSimulator(this.filter, this.request, true);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(((UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUsername())
				.isEqualTo(USERNAME);
		assertThat(SecurityContextHolder.getContext().getAuthentication().isAuthenticated()).isFalse();
		assertThat(this.request.getAttribute(RequestAttributeSecurityContextRepository.DEFAULT_REQUEST_ATTR_NAME))
				.isNotNull();
	}

	@Test
	public void testNormalOperationWhenPasswordNotAlreadyEncodedAndWithoutReAuthentication() throws Exception {
		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, PASSWORD, "GET", REQUEST_URI,
				QOP, NONCE, NC, CNONCE);
		this.request.addHeader("Authorization",
				createAuthorizationHeader(USERNAME, REALM, NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));
		this.filter.setCreateAuthenticatedToken(true);
		executeFilterInContainerSimulator(this.filter, this.request, true);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(((UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUsername())
				.isEqualTo(USERNAME);
		assertThat(SecurityContextHolder.getContext().getAuthentication().isAuthenticated()).isTrue();
		assertThat(SecurityContextHolder.getContext().getAuthentication().getAuthorities())
				.isEqualTo(AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"));
		assertThat(this.request.getAttribute(RequestAttributeSecurityContextRepository.DEFAULT_REQUEST_ATTR_NAME))
				.isNotNull();
	}

	@Test
	public void otherAuthorizationSchemeIsIgnored() throws Exception {
		this.request.addHeader("Authorization", "SOME_OTHER_AUTHENTICATION_SCHEME");
		executeFilterInContainerSimulator(this.filter, this.request, true);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void startupDetectsMissingAuthenticationEntryPoint() {
		DigestAuthenticationFilter filter = new DigestAuthenticationFilter();
		filter.setUserDetailsService(mock(UserDetailsService.class));
		assertThatIllegalArgumentException().isThrownBy(filter::afterPropertiesSet);
	}

	@Test
	public void startupDetectsMissingUserDetailsService() {
		DigestAuthenticationFilter filter = new DigestAuthenticationFilter();
		filter.setAuthenticationEntryPoint(new DigestAuthenticationEntryPoint());
		assertThatIllegalArgumentException().isThrownBy(filter::afterPropertiesSet);
	}

	@Test
	public void authenticateUsesCustomSecurityContextHolderStrategy() throws Exception {
		SecurityContextHolderStrategy securityContextHolderStrategy = spy(new MockSecurityContextHolderStrategy());
		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, PASSWORD, "GET", REQUEST_URI,
				QOP, NONCE, NC, CNONCE);
		this.request.addHeader("Authorization",
				createAuthorizationHeader(USERNAME, REALM, NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));
		this.filter.setSecurityContextHolderStrategy(securityContextHolderStrategy);
		executeFilterInContainerSimulator(this.filter, this.request, true);
		verify(securityContextHolderStrategy).setContext(any());
	}

	@Test
	public void successfulLoginThenFailedLoginResultsInSessionLosingToken() throws Exception {
		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, PASSWORD, "GET", REQUEST_URI,
				QOP, NONCE, NC, CNONCE);
		this.request.addHeader("Authorization",
				createAuthorizationHeader(USERNAME, REALM, NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));
		executeFilterInContainerSimulator(this.filter, this.request, true);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		// Now retry, giving an invalid nonce
		responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, "WRONG_PASSWORD", "GET", REQUEST_URI,
				QOP, NONCE, NC, CNONCE);
		this.request = new MockHttpServletRequest();
		this.request.addHeader("Authorization",
				createAuthorizationHeader(USERNAME, REALM, NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));
		MockHttpServletResponse response = executeFilterInContainerSimulator(this.filter, this.request, false);
		// Check we lost our previous authentication
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void wrongCnonceBasedOnDigestReturnsForbidden() throws Exception {
		String cnonce = "NOT_SAME_AS_USED_FOR_DIGEST_COMPUTATION";
		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, PASSWORD, "GET", REQUEST_URI,
				QOP, NONCE, NC, "DIFFERENT_CNONCE");
		this.request.addHeader("Authorization",
				createAuthorizationHeader(USERNAME, REALM, NONCE, REQUEST_URI, responseDigest, QOP, NC, cnonce));
		MockHttpServletResponse response = executeFilterInContainerSimulator(this.filter, this.request, false);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void wrongDigestReturnsForbidden() throws Exception {
		String password = "WRONG_PASSWORD";
		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, password, "GET", REQUEST_URI,
				QOP, NONCE, NC, CNONCE);
		this.request.addHeader("Authorization",
				createAuthorizationHeader(USERNAME, REALM, NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));
		MockHttpServletResponse response = executeFilterInContainerSimulator(this.filter, this.request, false);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void wrongRealmReturnsForbidden() throws Exception {
		String realm = "WRONG_REALM";
		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, realm, PASSWORD, "GET", REQUEST_URI,
				QOP, NONCE, NC, CNONCE);
		this.request.addHeader("Authorization",
				createAuthorizationHeader(USERNAME, realm, NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));
		MockHttpServletResponse response = executeFilterInContainerSimulator(this.filter, this.request, false);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	@Test
	public void wrongUsernameReturnsForbidden() throws Exception {
		String responseDigest = DigestAuthUtils.generateDigest(false, "NOT_A_KNOWN_USER", REALM, PASSWORD, "GET",
				REQUEST_URI, QOP, NONCE, NC, CNONCE);
		this.request.addHeader("Authorization",
				createAuthorizationHeader(USERNAME, REALM, NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));
		MockHttpServletResponse response = executeFilterInContainerSimulator(this.filter, this.request, false);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
		assertThat(response.getStatus()).isEqualTo(401);
	}

	// SEC-3108
	@Test
	public void authenticationCreatesEmptyContext() throws Exception {
		SecurityContext existingContext = SecurityContextHolder.createEmptyContext();
		TestingAuthenticationToken existingAuthentication = new TestingAuthenticationToken("existingauthenitcated",
				"pass", "ROLE_USER");
		existingContext.setAuthentication(existingAuthentication);
		SecurityContextHolder.setContext(existingContext);
		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, PASSWORD, "GET", REQUEST_URI,
				QOP, NONCE, NC, CNONCE);
		this.request.addHeader("Authorization",
				createAuthorizationHeader(USERNAME, REALM, NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));
		this.filter.setCreateAuthenticatedToken(true);
		executeFilterInContainerSimulator(this.filter, this.request, true);
		assertThat(existingAuthentication).isSameAs(existingContext.getAuthentication());
	}

	@Test
	public void testSecurityContextRepository() throws Exception {
		SecurityContextRepository securityContextRepository = mock(SecurityContextRepository.class);
		ArgumentCaptor<SecurityContext> contextArg = ArgumentCaptor.forClass(SecurityContext.class);
		String responseDigest = DigestAuthUtils.generateDigest(false, USERNAME, REALM, PASSWORD, "GET", REQUEST_URI,
				QOP, NONCE, NC, CNONCE);
		this.request.addHeader("Authorization",
				createAuthorizationHeader(USERNAME, REALM, NONCE, REQUEST_URI, responseDigest, QOP, NC, CNONCE));
		this.filter.setSecurityContextRepository(securityContextRepository);
		this.filter.setCreateAuthenticatedToken(true);
		MockHttpServletResponse response = executeFilterInContainerSimulator(this.filter, this.request, true);
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNotNull();
		assertThat(((UserDetails) SecurityContextHolder.getContext().getAuthentication().getPrincipal()).getUsername())
				.isEqualTo(USERNAME);
		assertThat(SecurityContextHolder.getContext().getAuthentication().isAuthenticated()).isTrue();
		assertThat(SecurityContextHolder.getContext().getAuthentication().getAuthorities())
				.isEqualTo(AuthorityUtils.createAuthorityList("ROLE_ONE", "ROLE_TWO"));
		verify(securityContextRepository).saveContext(contextArg.capture(), eq(this.request), eq(response));
		assertThat(contextArg.getValue().getAuthentication().getName()).isEqualTo(USERNAME);
	}

}
