/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.oauth2.client.web.client;

import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.oauth2.client.ClientAuthorizationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizationFailureHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthorizationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.test.web.client.RequestMatcher;
import org.springframework.test.web.client.ResponseCreator;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestClient;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.headerDoesNotExist;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withStatus;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

/**
 * Tests for {@link OAuth2ClientHttpRequestInterceptor}.
 *
 * @author Steve Riesenberg
 */
@ExtendWith(MockitoExtension.class)
public class OAuth2ClientHttpRequestInterceptorTests {

	private static final String REQUEST_URI = "/resources";

	private static final String ERROR_DESCRIPTION = "The request requires higher privileges than provided by the access token.";

	private static final String ERROR_URI = "https://tools.ietf.org/html/rfc6750#section-3.1";

	@Mock
	private OAuth2AuthorizedClientManager authorizedClientManager;

	@Mock
	private OAuth2AuthorizationFailureHandler authorizationFailureHandler;

	@Mock
	private OAuth2AuthorizedClientRepository authorizedClientRepository;

	@Mock
	private OAuth2AuthorizedClientService authorizedClientService;

	@Mock
	private OAuth2ClientHttpRequestInterceptor.ClientRegistrationIdResolver clientRegistrationIdResolver;

	@Mock
	private OAuth2ClientHttpRequestInterceptor.PrincipalResolver principalResolver;

	@Captor
	private ArgumentCaptor<OAuth2AuthorizeRequest> authorizeRequestCaptor;

	@Captor
	private ArgumentCaptor<OAuth2AuthorizationException> authorizationExceptionCaptor;

	@Captor
	private ArgumentCaptor<Authentication> authenticationCaptor;

	@Captor
	private ArgumentCaptor<Map<String, Object>> attributesCaptor;

	private ClientRegistration clientRegistration;

	private OAuth2AuthorizedClient authorizedClient;

	private OAuth2AuthenticationToken principal;

	private OAuth2ClientHttpRequestInterceptor requestInterceptor;

	private MockRestServiceServer server;

	private RestClient restClient;

	@BeforeEach
	public void setUp() {
		this.clientRegistration = TestClientRegistrations.clientRegistration().build();
		OAuth2AccessToken accessToken = TestOAuth2AccessTokens.scopes("read", "write");
		this.authorizedClient = new OAuth2AuthorizedClient(this.clientRegistration, "user", accessToken);
		List<GrantedAuthority> authorities = AuthorityUtils.createAuthorityList("OAUTH2_USER");
		Map<String, Object> attributes = Map.of(StandardClaimNames.SUB, "user");
		OAuth2User user = new DefaultOAuth2User(authorities, attributes, StandardClaimNames.SUB);
		this.principal = new OAuth2AuthenticationToken(user, authorities, "login-client");
		this.requestInterceptor = new OAuth2ClientHttpRequestInterceptor(this.authorizedClientManager);
	}

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
		RequestContextHolder.resetRequestAttributes();
	}

	@Test
	public void constructorWhenAuthorizedClientManagerIsNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new OAuth2ClientHttpRequestInterceptor(null))
			.withMessage("authorizedClientManager cannot be null");
	}

	@Test
	public void setAuthorizationFailureHandlerWhenNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.requestInterceptor.setAuthorizationFailureHandler(null))
			.withMessage("authorizationFailureHandler cannot be null");
	}

	@Test
	public void authorizationFailureHandlerWhenAuthorizedClientRepositoryIsNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> OAuth2ClientHttpRequestInterceptor
				.authorizationFailureHandler((OAuth2AuthorizedClientRepository) null))
			.withMessage("authorizedClientRepository cannot be null");
	}

	@Test
	public void authorizationFailureHandlerWhenAuthorizedClientServiceIsNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> OAuth2ClientHttpRequestInterceptor
				.authorizationFailureHandler((OAuth2AuthorizedClientService) null))
			.withMessage("authorizedClientService cannot be null");
	}

	@Test
	public void setClientRegistrationIdResolverWhenNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.requestInterceptor.setClientRegistrationIdResolver(null))
			.withMessage("clientRegistrationIdResolver cannot be null");
	}

	@Test
	public void setPrincipalResolverWhenNullThenThrowsIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.requestInterceptor.setPrincipalResolver(null))
			.withMessage("principalResolver cannot be null");
	}

	@Test
	public void interceptWhenAnonymousThenAuthorizationHeaderNotSet() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(headerDoesNotExist(HttpHeaders.AUTHORIZATION))
			.andRespond(withApplicationJson());
		performRequest(withDefaults());
		this.server.verify();
		verifyNoInteractions(this.authorizedClientManager, this.authorizationFailureHandler);
	}

	@Test
	public void interceptWhenAnonymousAndAuthorizedThenAuthorizationHeaderSet() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withApplicationJson());
		performRequest(withClientRegistrationId());
		this.server.verify();
		verify(this.authorizedClientManager).authorize(this.authorizeRequestCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager);
		verifyNoInteractions(this.authorizationFailureHandler);
		OAuth2AuthorizeRequest authorizeRequest = this.authorizeRequestCaptor.getValue();
		assertThat(authorizeRequest.getClientRegistrationId()).isEqualTo(this.clientRegistration.getRegistrationId());
		assertThat(authorizeRequest.getPrincipal()).isInstanceOf(AnonymousAuthenticationToken.class);
	}

	@Test
	public void interceptWhenAnonymousAndNotAuthorizedThenAuthorizationHeaderNotSet() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class))).willReturn(null);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(headerDoesNotExist(HttpHeaders.AUTHORIZATION))
			.andRespond(withApplicationJson());
		performRequest(withClientRegistrationId());
		this.server.verify();
		verify(this.authorizedClientManager).authorize(this.authorizeRequestCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager);
		verifyNoInteractions(this.authorizationFailureHandler);
		OAuth2AuthorizeRequest authorizeRequest = this.authorizeRequestCaptor.getValue();
		assertThat(authorizeRequest.getClientRegistrationId()).isEqualTo(this.clientRegistration.getRegistrationId());
		assertThat(authorizeRequest.getPrincipal()).isInstanceOf(AnonymousAuthenticationToken.class);
	}

	@Test
	public void interceptWhenAuthenticatedAndAuthorizedThenAuthorizationHeaderSet() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withApplicationJson());
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(this.principal);
		SecurityContextHolder.setContext(securityContext);
		performRequest(withClientRegistrationId());
		this.server.verify();
		verify(this.authorizedClientManager).authorize(this.authorizeRequestCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager);
		verifyNoInteractions(this.authorizationFailureHandler);
		OAuth2AuthorizeRequest authorizeRequest = this.authorizeRequestCaptor.getValue();
		assertThat(authorizeRequest.getClientRegistrationId()).isEqualTo(this.clientRegistration.getRegistrationId());
		assertThat(authorizeRequest.getPrincipal()).isEqualTo(this.principal);
	}

	@Test
	public void interceptWhenAuthenticatedAndNotAuthorizedThenAuthorizationHeaderNotSet() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class))).willReturn(null);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(headerDoesNotExist(HttpHeaders.AUTHORIZATION))
			.andRespond(withApplicationJson());
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(this.principal);
		SecurityContextHolder.setContext(securityContext);
		performRequest(withClientRegistrationId());
		this.server.verify();
		verify(this.authorizedClientManager).authorize(this.authorizeRequestCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager);
		verifyNoInteractions(this.authorizationFailureHandler);
		OAuth2AuthorizeRequest authorizeRequest = this.authorizeRequestCaptor.getValue();
		assertThat(authorizeRequest.getClientRegistrationId()).isEqualTo(this.clientRegistration.getRegistrationId());
		assertThat(authorizeRequest.getPrincipal()).isInstanceOf(OAuth2AuthenticationToken.class);
	}

	@Test
	public void interceptWhenAnonymousAndUnauthorizedThenDoesNotCallAuthorizationFailureHandler() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(headerDoesNotExist(HttpHeaders.AUTHORIZATION))
			.andRespond(withWwwAuthenticateHeader(HttpStatus.UNAUTHORIZED));
		assertThatExceptionOfType(HttpClientErrorException.class).isThrownBy(() -> performRequest(withDefaults()))
			.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED));
		this.server.verify();
		verifyNoInteractions(this.authorizedClientManager, this.authorizationFailureHandler);
	}

	@Test
	public void interceptWhenAnonymousAndOAuth2ErrorInWwwAuthenticateHeaderThenCallsAuthorizationFailureHandlerWithInsufficientScopeError() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withWwwAuthenticateHeader(HttpStatus.OK));
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		performRequest(withClientRegistrationId());
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizationFailureHandler);
		assertThat(this.authorizationExceptionCaptor.getValue()).isInstanceOfSatisfying(
				ClientAuthorizationException.class,
				hasOAuth2Error(OAuth2ErrorCodes.INSUFFICIENT_SCOPE, ERROR_DESCRIPTION));
		assertThat(this.authenticationCaptor.getValue()).isInstanceOf(AnonymousAuthenticationToken.class);
		assertThat(this.attributesCaptor.getValue()).containsExactly(entry(HttpServletRequest.class.getName(), request),
				entry(HttpServletResponse.class.getName(), response));
	}

	@Test
	public void interceptWhenAuthenticatedAndOAuth2ErrorInWwwAuthenticateHeaderThenCallsAuthorizationFailureHandlerWithInsufficientScopeError() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withWwwAuthenticateHeader(HttpStatus.OK));
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(this.principal);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		performRequest(withClientRegistrationId());
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizationFailureHandler);
		assertThat(this.authorizationExceptionCaptor.getValue()).isInstanceOfSatisfying(
				ClientAuthorizationException.class,
				hasOAuth2Error(OAuth2ErrorCodes.INSUFFICIENT_SCOPE, ERROR_DESCRIPTION));
		assertThat(this.authenticationCaptor.getValue()).isEqualTo(this.principal);
		assertThat(this.attributesCaptor.getValue()).containsExactly(entry(HttpServletRequest.class.getName(), request),
				entry(HttpServletResponse.class.getName(), response));
	}

	@Test
	public void interceptWhenUnauthorizedAndOAuth2ErrorInWwwAuthenticateHeaderThenCallsAuthorizationFailureHandlerWithInsufficientScopeError() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withWwwAuthenticateHeader(HttpStatus.UNAUTHORIZED));
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(this.principal);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		assertThatExceptionOfType(HttpClientErrorException.class)
			.isThrownBy(() -> performRequest(withClientRegistrationId()))
			.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED));
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizationFailureHandler);
		assertThat(this.authorizationExceptionCaptor.getValue()).isInstanceOfSatisfying(
				ClientAuthorizationException.class,
				hasOAuth2Error(OAuth2ErrorCodes.INSUFFICIENT_SCOPE, ERROR_DESCRIPTION));
		assertThat(this.authenticationCaptor.getValue()).isEqualTo(this.principal);
		assertThat(this.attributesCaptor.getValue()).containsExactly(entry(HttpServletRequest.class.getName(), request),
				entry(HttpServletResponse.class.getName(), response));
	}

	@Test
	public void interceptWhenForbiddenAndOAuth2ErrorInWwwAuthenticateHeaderThenCallsAuthorizationFailureHandlerWithInsufficientScopeError() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withWwwAuthenticateHeader(HttpStatus.FORBIDDEN));
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(this.principal);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		assertThatExceptionOfType(HttpClientErrorException.class)
			.isThrownBy(() -> performRequest(withClientRegistrationId()))
			.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN));
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizationFailureHandler);
		assertThat(this.authorizationExceptionCaptor.getValue()).isInstanceOfSatisfying(
				ClientAuthorizationException.class,
				hasOAuth2Error(OAuth2ErrorCodes.INSUFFICIENT_SCOPE, ERROR_DESCRIPTION));
		assertThat(this.authenticationCaptor.getValue()).isEqualTo(this.principal);
		assertThat(this.attributesCaptor.getValue()).containsExactly(entry(HttpServletRequest.class.getName(), request),
				entry(HttpServletResponse.class.getName(), response));
	}

	@Test
	public void interceptWhenUnauthorizedThenCallsAuthorizationFailureHandlerWithInvalidTokenError() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withStatus(HttpStatus.UNAUTHORIZED));
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(this.principal);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		assertThatExceptionOfType(HttpClientErrorException.class)
			.isThrownBy(() -> performRequest(withClientRegistrationId()))
			.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED));
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizationFailureHandler);
		assertThat(this.authorizationExceptionCaptor.getValue()).isInstanceOfSatisfying(
				ClientAuthorizationException.class, hasOAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN, null));
		assertThat(this.authenticationCaptor.getValue()).isEqualTo(this.principal);
		assertThat(this.attributesCaptor.getValue()).containsExactly(entry(HttpServletRequest.class.getName(), request),
				entry(HttpServletResponse.class.getName(), response));
	}

	@Test
	public void interceptWhenForbiddenThenCallsAuthorizationFailureHandlerWithInsufficientScopeError() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withStatus(HttpStatus.FORBIDDEN));
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(this.principal);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		assertThatExceptionOfType(HttpClientErrorException.class)
			.isThrownBy(() -> performRequest(withClientRegistrationId()))
			.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN));
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizationFailureHandler);
		assertThat(this.authorizationExceptionCaptor.getValue()).isInstanceOfSatisfying(
				ClientAuthorizationException.class, hasOAuth2Error(OAuth2ErrorCodes.INSUFFICIENT_SCOPE, null));
		assertThat(this.authenticationCaptor.getValue()).isEqualTo(this.principal);
		assertThat(this.attributesCaptor.getValue()).containsExactly(entry(HttpServletRequest.class.getName(), request),
				entry(HttpServletResponse.class.getName(), response));
	}

	@Test
	public void interceptWhenInternalServerErrorThenDoesNotCallAuthorizationFailureHandler() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withStatus(HttpStatus.INTERNAL_SERVER_ERROR));
		assertThatExceptionOfType(HttpServerErrorException.class)
			.isThrownBy(() -> performRequest(withClientRegistrationId()))
			.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR));
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verifyNoMoreInteractions(this.authorizedClientManager);
		verifyNoInteractions(this.authorizationFailureHandler);
	}

	@Test
	public void interceptWhenAuthorizationExceptionThenCallsAuthorizationFailureHandlerWithException() {
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		OAuth2AuthorizationException authorizationException = new OAuth2AuthorizationException(
				new OAuth2Error(OAuth2ErrorCodes.INVALID_TOKEN));
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withException(authorizationException));
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(this.principal);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		assertThatExceptionOfType(OAuth2AuthorizationException.class)
			.isThrownBy(() -> performRequest(withClientRegistrationId()))
			.isEqualTo(authorizationException);
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizationFailureHandler).onAuthorizationFailure(this.authorizationExceptionCaptor.capture(),
				this.authenticationCaptor.capture(), this.attributesCaptor.capture());
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizationFailureHandler);
		assertThat(this.authorizationExceptionCaptor.getValue()).isEqualTo(authorizationException);
		assertThat(this.authenticationCaptor.getValue()).isEqualTo(this.principal);
		assertThat(this.attributesCaptor.getValue()).containsExactly(entry(HttpServletRequest.class.getName(), request),
				entry(HttpServletResponse.class.getName(), response));
	}

	@Test
	public void interceptWhenUnauthorizedAndAuthorizationFailureHandlerSetWithAuthorizedClientRepositoryThenAuthorizedClientRemoved() {
		this.requestInterceptor.setAuthorizationFailureHandler(
				OAuth2ClientHttpRequestInterceptor.authorizationFailureHandler(this.authorizedClientRepository));
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withStatus(HttpStatus.UNAUTHORIZED));
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(this.principal);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		assertThatExceptionOfType(HttpClientErrorException.class)
			.isThrownBy(() -> performRequest(withClientRegistrationId()))
			.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED));
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizedClientRepository).removeAuthorizedClient(this.clientRegistration.getRegistrationId(),
				this.principal, request, response);
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizedClientRepository);
	}

	@Test
	public void interceptWhenUnauthorizedAndAuthorizationFailureHandlerSetWithAuthorizedClientServiceThenAuthorizedClientRemoved() {
		this.requestInterceptor.setAuthorizationFailureHandler(
				OAuth2ClientHttpRequestInterceptor.authorizationFailureHandler(this.authorizedClientService));
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withStatus(HttpStatus.UNAUTHORIZED));
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(this.principal);
		SecurityContextHolder.setContext(securityContext);
		MockHttpServletRequest request = new MockHttpServletRequest();
		MockHttpServletResponse response = new MockHttpServletResponse();
		RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request, response));
		assertThatExceptionOfType(HttpClientErrorException.class)
			.isThrownBy(() -> performRequest(withClientRegistrationId()))
			.satisfies((ex) -> assertThat(ex.getStatusCode()).isEqualTo(HttpStatus.UNAUTHORIZED));
		this.server.verify();
		verify(this.authorizedClientManager).authorize(any(OAuth2AuthorizeRequest.class));
		verify(this.authorizedClientService).removeAuthorizedClient(this.clientRegistration.getRegistrationId(),
				this.principal.getName());
		verifyNoMoreInteractions(this.authorizedClientManager, this.authorizedClientService);
	}

	@Test
	public void interceptWhenCustomClientRegistrationIdResolverSetThenUsed() {
		this.requestInterceptor.setClientRegistrationIdResolver(this.clientRegistrationIdResolver);
		this.requestInterceptor.setAuthorizationFailureHandler(this.authorizationFailureHandler);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		String clientRegistrationId = "test-client";
		given(this.clientRegistrationIdResolver.resolve(any(HttpRequest.class))).willReturn(clientRegistrationId);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withApplicationJson());
		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(this.principal);
		SecurityContextHolder.setContext(securityContext);
		performRequest(withDefaults());
		this.server.verify();
		verify(this.authorizedClientManager).authorize(this.authorizeRequestCaptor.capture());
		verify(this.clientRegistrationIdResolver).resolve(any(HttpRequest.class));
		verifyNoMoreInteractions(this.authorizedClientManager, this.clientRegistrationIdResolver);
		verifyNoInteractions(this.authorizationFailureHandler);
		OAuth2AuthorizeRequest authorizeRequest = this.authorizeRequestCaptor.getValue();
		assertThat(authorizeRequest.getClientRegistrationId()).isEqualTo(clientRegistrationId);
		assertThat(authorizeRequest.getPrincipal()).isEqualTo(this.principal);
	}

	@Test
	public void interceptWhenCustomPrincipalResolverSetThenUsed() {
		this.requestInterceptor.setPrincipalResolver(this.principalResolver);
		given(this.authorizedClientManager.authorize(any(OAuth2AuthorizeRequest.class)))
			.willReturn(this.authorizedClient);

		bindToRestClient(withRequestInterceptor());
		this.server.expect(requestTo(REQUEST_URI))
			.andExpect(hasAuthorizationHeader(this.authorizedClient.getAccessToken()))
			.andRespond(withApplicationJson());
		given(this.principalResolver.resolve(any(HttpRequest.class))).willReturn(this.principal);
		performRequest(withClientRegistrationId());
		this.server.verify();
		verify(this.authorizedClientManager).authorize(this.authorizeRequestCaptor.capture());
		verify(this.principalResolver).resolve(any(HttpRequest.class));
		verifyNoMoreInteractions(this.authorizedClientManager, this.principalResolver);
		OAuth2AuthorizeRequest authorizeRequest = this.authorizeRequestCaptor.getValue();
		assertThat(authorizeRequest.getClientRegistrationId()).isEqualTo(this.clientRegistration.getRegistrationId());
		assertThat(authorizeRequest.getPrincipal()).isEqualTo(this.principal);
	}

	private void bindToRestClient(Consumer<RestClient.Builder> customizer) {
		RestClient.Builder builder = RestClient.builder();
		customizer.accept(builder);
		this.server = MockRestServiceServer.bindTo(builder).build();
		this.restClient = builder.build();
	}

	private Consumer<RestClient.Builder> withRequestInterceptor() {
		return (builder) -> builder.requestInterceptor(this.requestInterceptor);
	}

	private static RequestMatcher hasAuthorizationHeader(OAuth2AccessToken accessToken) {
		String tokenType = accessToken.getTokenType().getValue();
		String tokenValue = accessToken.getTokenValue();
		return header(HttpHeaders.AUTHORIZATION, "%s %s".formatted(tokenType, tokenValue));
	}

	private static ResponseCreator withApplicationJson() {
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_JSON);
		return withSuccess().headers(headers).body("{}");
	}

	private static ResponseCreator withWwwAuthenticateHeader(HttpStatus httpStatus) {
		String wwwAuthenticateHeader = "Bearer error=\"insufficient_scope\", "
				+ "error_description=\"The request requires higher privileges than provided by the access token.\", "
				+ "error_uri=\"https://tools.ietf.org/html/rfc6750#section-3.1\"";
		HttpHeaders headers = new HttpHeaders();
		headers.set(HttpHeaders.WWW_AUTHENTICATE, wwwAuthenticateHeader);
		return withStatus(httpStatus).headers(headers);
	}

	private static ResponseCreator withException(OAuth2AuthorizationException ex) {
		return (request) -> {
			throw ex;
		};
	}

	private void performRequest(Consumer<RestClient.RequestHeadersSpec<?>> customizer) {
		RestClient.RequestHeadersSpec<?> spec = this.restClient.get().uri(REQUEST_URI);
		customizer.accept(spec);
		spec.retrieve().toBodilessEntity();
	}

	private static Consumer<RestClient.RequestHeadersSpec<?>> withDefaults() {
		return (spec) -> {
		};
	}

	private Consumer<RestClient.RequestHeadersSpec<?>> withClientRegistrationId() {
		return (spec) -> spec.attributes(RequestAttributeClientRegistrationIdResolver
			.clientRegistrationId(this.clientRegistration.getRegistrationId()));
	}

	private Consumer<ClientAuthorizationException> hasOAuth2Error(String errorCode, String errorDescription) {
		return (ex) -> {
			assertThat(ex.getClientRegistrationId()).isEqualTo(this.clientRegistration.getRegistrationId());
			assertThat(ex.getError().getErrorCode()).isEqualTo(errorCode);
			assertThat(ex.getError().getDescription()).isEqualTo(errorDescription);
			assertThat(ex.getError().getUri()).isEqualTo(ERROR_URI);
			assertThat(ex).hasNoCause();
			assertThat(ex).hasMessageContaining(errorCode);
		};
	}

}
