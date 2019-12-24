/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.config.http;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeAuthenticationProvider;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.core.oidc.TestOidcIdTokens.idToken;
import static org.springframework.security.oauth2.jwt.TestJwts.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

/**
 * Tests for {@link OAuth2LoginBeanDefinitionParser}.
 *
 * @author Ruby Hartono
 */
public class OAuth2LoginBeanDefinitionParserTests {
	private static final String CONFIG_LOCATION_PREFIX = "classpath:org/springframework/security/config/http/OAuth2LoginBeanDefinitionParserTests";

	@Rule
	public final SpringTestRule spring = new SpringTestRule();

	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;

	@Autowired
	SecurityContextRepository securityContextRepository;

	@Autowired(required = false)
	private AuthenticationSuccessListener authenticationSuccessListener;

	@Autowired(required = false)
	private OidcAuthorizationCodeAuthenticationProvider oidcAuthorizationCodeAuthenticationProvider;

	private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository = new HttpSessionOAuth2AuthorizationRequestRepository();

	@Autowired
	private MockMvc mvc;

	// gh-5347
	@Test
	public void requestWhenSingleClientRegistrationThenAutoRedirect() throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration")).autowire();

		this.mvc.perform(get("/")).andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("http://localhost/oauth2/authorization/google-login"));
	}

	// gh-5347
	@Test
	public void requestWhenSingleClientRegistrationAndRequestFaviconNotAuthenticatedThenRedirectDefaultLoginPage()
			throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration")).autowire();

		this.mvc.perform(get("/favicon.ico").accept(new MediaType("image", "*"))).andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("http://localhost/login"));
	}

	// gh-6812
	@Test
	public void requestWhenSingleClientRegistrationAndRequestXHRNotAuthenticatedThenDoesNotRedirectForAuthorization()
			throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration")).autowire();

		this.mvc.perform(get("/").header("X-Requested-With", "XMLHttpRequest")).andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("http://localhost/login"));
	}

	@Test
	public void requestWhenSingleClientRegistrationWithNonExistanceAuthenticationThenRedirectToDefaultLoginError()
			throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration")).autowire();

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("code", "code123");
		params.add("state", "state123");
		this.mvc.perform(get("/login/oauth2/code/google").params(params)).andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("/login?error"));
	}

	@Test
	public void successLoginWhenSingleClientRegistrationThenRedirectToDefaultUrl() throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration-WithTestConfiguration")).autowire();

		MockHttpSession session = new MockHttpSession();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setServletPath("/login/oauth2/code/google");
		request.setSession(session);
		MockHttpServletResponse response = new MockHttpServletResponse();

		OAuth2AuthorizationRequest authRequest = createOAuth2AuthorizationRequest(
				clientRegistrationRepository.findByRegistrationId("google-login"));
		authorizationRequestRepository.saveAuthorizationRequest(authRequest, request, response);

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("code", "code123");
		params.add("state", "state123");
		this.mvc.perform(get("/login/oauth2/code/google").params(params).session(session))
				.andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/"));

		Authentication authentication = this.securityContextRepository
				.loadContext(new HttpRequestResponseHolder(request, response)).getAuthentication();
		assertThat(authentication.getAuthorities()).hasSize(1);
		assertThat(authentication.getAuthorities()).first().isInstanceOf(OAuth2UserAuthority.class)
				.hasToString("ROLE_USER");
	}

	// gh-6009
	@Test
	public void successLoginWhenSingleClientRegistrationThenAuthenticationSuccessEventPublished() throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration-WithTestConfiguration")).autowire();

		MockHttpSession session = new MockHttpSession();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setServletPath("/login/oauth2/code/google");
		request.setSession(session);
		MockHttpServletResponse response = new MockHttpServletResponse();

		OAuth2AuthorizationRequest authRequest = createOAuth2AuthorizationRequest(
				clientRegistrationRepository.findByRegistrationId("google-login"));
		authorizationRequestRepository.saveAuthorizationRequest(authRequest, request, response);

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("code", "code123");
		params.add("state", "state123");
		this.mvc.perform(get("/login/oauth2/code/google").params(params).session(session));

		// assertions
		assertThat(authenticationSuccessListener.events).isNotEmpty();
		assertThat(authenticationSuccessListener.events).hasSize(1);
		assertThat(authenticationSuccessListener.events.get(0)).isInstanceOf(AuthenticationSuccessEvent.class);
	}

	@Test
	public void successOidcLoginWhenSingleClientRegistrationThenRedirectToDefaultUrl() throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration-WithTestConfiguration")).autowire();
		// set the jwt decoder to test instance
		oidcAuthorizationCodeAuthenticationProvider.setJwtDecoderFactory(new DummyOAuth2OidcJwtDecoderFactory());

		MockHttpSession session = new MockHttpSession();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setServletPath("/login/oauth2/code/google");
		request.setSession(session);
		MockHttpServletResponse response = new MockHttpServletResponse();

		OAuth2AuthorizationRequest authRequest = createOAuth2AuthorizationRequest(
				clientRegistrationRepository.findByRegistrationId("google-login"), "openid");
		authorizationRequestRepository.saveAuthorizationRequest(authRequest, request, response);

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("code", "code123");
		params.add("state", "state123");
		this.mvc.perform(get("/login/oauth2/code/google").params(params).session(session))
				.andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/"));
	}

	@Test
	public void failedOidcLoginWhenSingleClientRegistrationThenRedirectToDefaultLoginError() throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration-WithTestConfiguration")).autowire();

		MockHttpSession session = new MockHttpSession();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setServletPath("/login/oauth2/code/google");
		request.setSession(session);
		MockHttpServletResponse response = new MockHttpServletResponse();

		OAuth2AuthorizationRequest authRequest = createOAuth2AuthorizationRequest(
				clientRegistrationRepository.findByRegistrationId("google-login"), "openid");
		authorizationRequestRepository.saveAuthorizationRequest(authRequest, request, response);

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("code", "code123");
		params.add("state", "state123");
		this.mvc.perform(get("/login/oauth2/code/google").params(params).session(session))
				.andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/login?error"));
	}

	@Test
	public void successLoginWhenSingleClientRegistrationAndCustomAuthoritiesThenRedirectToDefaultUrlWithCorrectAuthorities()
			throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration-WithCustomGrantedAuthorities")).autowire();

		MockHttpSession session = new MockHttpSession();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setServletPath("/login/oauth2/code/google");
		request.setSession(session);
		MockHttpServletResponse response = new MockHttpServletResponse();

		OAuth2AuthorizationRequest authRequest = createOAuth2AuthorizationRequest(
				clientRegistrationRepository.findByRegistrationId("google-login"));
		authorizationRequestRepository.saveAuthorizationRequest(authRequest, request, response);

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("code", "code123");
		params.add("state", "state123");
		this.mvc.perform(get("/login/oauth2/code/google").params(params).session(session))
				.andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/"));

		Authentication authentication = this.securityContextRepository
				.loadContext(new HttpRequestResponseHolder(request, response)).getAuthentication();
		assertThat(authentication.getAuthorities()).hasSize(2);
		assertThat(authentication.getAuthorities()).first().hasToString("ROLE_USER");
		assertThat(authentication.getAuthorities()).last().hasToString("ROLE_OAUTH2_USER");
	}

	@Test
	public void successOidcLoginWhenSingleClientRegistrationAndCustomAuthoritiesThenRedirectToDefaultUrlWithCorrectAuthorities()
			throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration-WithCustomGrantedAuthorities")).autowire();

		// set the jwt decoder to test instance
		oidcAuthorizationCodeAuthenticationProvider.setJwtDecoderFactory(new DummyOAuth2OidcJwtDecoderFactory());

		MockHttpSession session = new MockHttpSession();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setServletPath("/login/oauth2/code/google");
		request.setSession(session);
		MockHttpServletResponse response = new MockHttpServletResponse();

		OAuth2AuthorizationRequest authRequest = createOAuth2AuthorizationRequest(
				clientRegistrationRepository.findByRegistrationId("google-login"), "openid");
		authorizationRequestRepository.saveAuthorizationRequest(authRequest, request, response);

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("code", "code123");
		params.add("state", "state123");
		this.mvc.perform(get("/login/oauth2/code/google").params(params).session(session))
				.andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/"));

		Authentication authentication = this.securityContextRepository
				.loadContext(new HttpRequestResponseHolder(request, response)).getAuthentication();
		assertThat(authentication.getAuthorities()).hasSize(2);
		assertThat(authentication.getAuthorities()).first().hasToString("ROLE_USER");
		assertThat(authentication.getAuthorities()).last().hasToString("ROLE_OIDC_USER");
	}

	// gh-5488
	@Test
	public void successLoginWhenSingleClientRegistrationAndCustomLoginProcessingUrlThenRedirectToDefaultUrlWithCorrectAuthorities()
			throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration-WithCustomLoginProcessingUrl")).autowire();

		MockHttpSession session = new MockHttpSession();
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "");
		request.setServletPath("/login/oauth2/google");
		request.setSession(session);
		MockHttpServletResponse response = new MockHttpServletResponse();

		OAuth2AuthorizationRequest authRequest = createOAuth2AuthorizationRequest(
				clientRegistrationRepository.findByRegistrationId("google-login"));
		authorizationRequestRepository.saveAuthorizationRequest(authRequest, request, response);

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("code", "code123");
		params.add("state", "state123");
		this.mvc.perform(get("/login/oauth2/google").params(params).session(session))
				.andExpect(status().is3xxRedirection()).andExpect(redirectedUrl("/"));

		Authentication authentication = this.securityContextRepository
				.loadContext(new HttpRequestResponseHolder(request, response)).getAuthentication();
		assertThat(authentication.getAuthorities()).hasSize(1);
		assertThat(authentication.getAuthorities()).first().isInstanceOf(OAuth2UserAuthority.class)
				.hasToString("ROLE_USER");
	}

	// gh-5521
	@Test
	public void successLoginWhenSingleClientRegistrationAndCustomAuthorizationRequestResolverThenRedirectToCustomAuthURI()
			throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration-WithCustomAuthorizationRequestResolver"))
				.autowire();

		this.mvc.perform(get("/oauth2/authorization/google")).andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl(DummyAuthorizationRequestResolver.REQUEST_URI));
	}

	// gh-5347
	@Test
	public void requestWhenMultipleClientsConfiguredThenRedirectDefaultLoginPage() throws Exception {
		this.spring.configLocations(this.xml("MultiClientRegistration")).autowire();

		this.mvc.perform(get("/")).andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("http://localhost/login"));
	}

	@Test
	public void successLoginWhenSingleClientRegistrationAndCustomLoginPageThenRedirectToCustomLoginPage()
			throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration-WithCustomLoginPage")).autowire();

		this.mvc.perform(get("/")).andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("http://localhost/custom-login"));
	}

	// gh-6802
	@Test
	public void requestWhenSingleClientRegistrationWithFormLoginPageThenRedirectDefaultLoginPage() throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration-WithFormLogin")).autowire();

		this.mvc.perform(get("/")).andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("http://localhost/login"));
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

	private OAuth2AuthorizationRequest createOAuth2AuthorizationRequest(ClientRegistration registration,
			String... scopes) {
		return OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri(registration.getProviderDetails().getAuthorizationUri())
				.clientId(registration.getClientId()).state("state123").redirectUri("http://localhost")
				.attributes(Collections.singletonMap(OAuth2ParameterNames.REGISTRATION_ID,
						registration.getRegistrationId()))
				.scope(scopes).build();
	}

	public static class DummyAccessTokenResponse
			implements OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> {

		public static final String ACCESS_TOKEN_VALUE = "accessToken123";

		@Override
		public OAuth2AccessTokenResponse getTokenResponse(
				OAuth2AuthorizationCodeGrantRequest authorizationGrantRequest) {
			Map<String, Object> additionalParameters = new HashMap<>();
			if (authorizationGrantRequest.getAuthorizationExchange().getAuthorizationRequest().getScopes()
					.contains("openid")) {
				additionalParameters.put(OidcParameterNames.ID_TOKEN, "token123");
			}
			return OAuth2AccessTokenResponse.withToken(ACCESS_TOKEN_VALUE).tokenType(OAuth2AccessToken.TokenType.BEARER)
					.additionalParameters(additionalParameters).build();
		}
	}

	public static class DummyOAuth2UserService implements OAuth2UserService<OAuth2UserRequest, OAuth2User> {

		@Override
		public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
			Map<String, Object> userAttributes = Collections.singletonMap("name", "spring");
			return new DefaultOAuth2User(Collections.singleton(new OAuth2UserAuthority(userAttributes)), userAttributes,
					"name");
		}

	}

	public static class DummyOAuth2OidcUserService implements OAuth2UserService<OidcUserRequest, OidcUser> {

		@Override
		public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
			OidcIdToken idToken = idToken().build();
			return new DefaultOidcUser(Collections.singleton(new OidcUserAuthority(idToken)), idToken);
		}

	}

	public static class AuthenticationSuccessListener implements ApplicationListener<AuthenticationSuccessEvent> {

		List<AuthenticationSuccessEvent> events = new ArrayList<>();

		@Override
		public void onApplicationEvent(AuthenticationSuccessEvent event) {
			events.add(event);
		}

	}

	public static class DummyOAuth2OidcJwtDecoderFactory implements JwtDecoderFactory<ClientRegistration> {

		@Override
		public JwtDecoder createDecoder(ClientRegistration context) {
			Map<String, Object> claims = new HashMap<>();
			claims.put(IdTokenClaimNames.SUB, "sub123");
			claims.put(IdTokenClaimNames.ISS, "http://localhost/iss");
			claims.put(IdTokenClaimNames.AUD, Arrays.asList("clientId", "a", "u", "d"));
			claims.put(IdTokenClaimNames.AZP, "clientId");
			Jwt jwt = jwt().claims(c -> c.putAll(claims)).build();
			JwtDecoder jwtDecoder = mock(JwtDecoder.class);
			when(jwtDecoder.decode(any())).thenReturn(jwt);
			return jwtDecoder;
		}

	}

	public static class DummyGrantedAuthoritiesMapper implements GrantedAuthoritiesMapper {

		@Override
		public Collection<? extends GrantedAuthority> mapAuthorities(
				Collection<? extends GrantedAuthority> authorities) {
			boolean isOidc = OidcUserAuthority.class.isInstance(authorities.iterator().next());
			List<GrantedAuthority> mappedAuthorities = new ArrayList<>(authorities);
			mappedAuthorities.add(new SimpleGrantedAuthority(isOidc ? "ROLE_OIDC_USER" : "ROLE_OAUTH2_USER"));
			return mappedAuthorities;
		}

	}

	public static class DummyAuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver {

		static final String REQUEST_URI = "https://accounts.google.com/o/oauth2/v2/auth?response_type=code&client_id=clientId&scope=openid+profile+email&state=state&redirect_uri=http%3A%2F%2Flocalhost%2Flogin%2Foauth2%2Fcode%2Fgoogle&custom-param1=custom-value1";

		private OAuth2AuthorizationRequest getRequest() {
			return OAuth2AuthorizationRequest.authorizationCode()
					.authorizationUri("https://accounts.google.com/authorize").clientId("client-id").state("adsfa")
					.authorizationRequestUri(REQUEST_URI).build();
		}

		@Override
		public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
			return getRequest();
		}

		@Override
		public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
			return getRequest();
		}

	}
}
