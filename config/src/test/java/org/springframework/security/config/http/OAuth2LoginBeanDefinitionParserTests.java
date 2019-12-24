/*
 * Copyright 2002-2020 the original author or authors.
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
import org.mockito.ArgumentCaptor;
import org.mockito.internal.util.MockUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.config.test.SpringTestRule;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationRequests;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.TestOAuth2Users;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.TestJwts;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.core.endpoint.TestOAuth2AccessTokenResponses.accessTokenResponse;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.lang.reflect.Field;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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
	private OAuth2LoginAuthenticationFilter oauth2LoginAuthenticationFilter;

	@Autowired(required = false)
	private OAuth2AuthorizedClientRepository oauth2AuthorizedClientRepository;

	@Autowired(required = false)
	private OAuth2AuthorizedClientService oauth2AuthorizedClientService;

	@Autowired
	SecurityContextRepository securityContextRepository;

	@Autowired(required = false)
	private ApplicationListener<AuthenticationSuccessEvent> authenticationSuccessListener;

	@Autowired(required = false)
	private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;

	@Autowired(required = false)
	private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> accessTokenResponseClient;

	@Autowired(required = false)
	private OAuth2UserService<OAuth2UserRequest, OAuth2User> oauth2UserService;

	@Autowired(required = false)
	private JwtDecoderFactory<ClientRegistration> jwtDecoderFactory;

	@Autowired(required = false)
	private OAuth2AuthorizationRequestResolver oauth2AuthorizationRequestResolver;

	@Autowired(required = false)
	private GrantedAuthoritiesMapper grantedAuthoritiesMapper;

	@Autowired(required = false)
	private AuthenticationFailureHandler authenticationFailureHandler;

	@Autowired(required = false)
	private AuthenticationSuccessHandler authenticationSuccessHandler;

	@Autowired
	private MockMvc mvc;

	@Test
	public void requestLoginWhenMultiClientRegistrationThenReturnLoginPageWithOauth2Login() throws Exception {
		this.spring.configLocations(this.xml("MultiClientRegistration")).autowire();

		MvcResult result = this.mvc.perform(get("/login")).andExpect(status().is2xxSuccessful()).andReturn();

		assertThat(result.getResponse().getContentAsString())
				.contains("<a href=\"/oauth2/authorization/google-login\">Google</a>");
		assertThat(result.getResponse().getContentAsString())
				.contains("<a href=\"/oauth2/authorization/github-login\">Github</a>");
	}

	// gh-5347
	@Test
	public void requestWhenSingleClientRegistrationThenAutoRedirect() throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration-WithinSameFile")).autowire();

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
	public void requestWhenAuthorizationRequestNotFoundThenThrowAuthenticationException() throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration-WithCustomAuthenticationFailureHandler"))
				.autowire();

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("code", "code123");
		params.add("state", "state123");
		this.mvc.perform(get("/login/oauth2/code/google").params(params));

		// assertions
		ArgumentCaptor<AuthenticationException> exceptionCaptor = ArgumentCaptor
				.forClass(AuthenticationException.class);
		verify(authenticationFailureHandler).onAuthenticationFailure(any(), any(), exceptionCaptor.capture());
		AuthenticationException excValue = exceptionCaptor.getValue();
		assertThat(excValue).isInstanceOf(OAuth2AuthenticationException.class);
		assertThat(((OAuth2AuthenticationException) excValue).getError().getErrorCode())
				.isEqualTo("authorization_request_not_found");
	}

	@Test
	public void requestWhenAuthorizationResponseValidThenAuthenticate() throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration-WithTestConfiguration")).autowire();
		OAuth2AccessTokenResponse accessTokenResponse = accessTokenResponse().build();
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);

		OAuth2User oauth2User = TestOAuth2Users.create();
		when(this.oauth2UserService.loadUser(any())).thenReturn(oauth2User);

		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2ParameterNames.REGISTRATION_ID, "google-login");
		OAuth2AuthorizationRequest authRequest = TestOAuth2AuthorizationRequests.request().attributes(attributes)
				.build();
		when(this.authorizationRequestRepository.removeAuthorizationRequest(any(), any())).thenReturn(authRequest);

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("code", "code123");
		params.add("state", authRequest.getState());
		this.mvc.perform(get("/login/oauth2/code/google").params(params)).andExpect(status().is2xxSuccessful());

		ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);
		verify(authenticationSuccessHandler).onAuthenticationSuccess(any(), any(), authenticationCaptor.capture());
		Authentication authenticationValue = authenticationCaptor.getValue();
		assertThat(authenticationValue.getAuthorities()).hasSize(1);
		assertThat(authenticationValue.getAuthorities()).first().isInstanceOf(SimpleGrantedAuthority.class)
				.hasToString("ROLE_USER");
	}

	// gh-6009
	@Test
	public void requestWhenAuthorizationResponseValidThenAuthenticationSuccessEventPublished() throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration-WithTestConfiguration")).autowire();
		OAuth2AccessTokenResponse accessTokenResponse = accessTokenResponse().build();
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);

		OAuth2User oauth2User = TestOAuth2Users.create();
		when(this.oauth2UserService.loadUser(any())).thenReturn(oauth2User);

		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2ParameterNames.REGISTRATION_ID, "google-login");
		OAuth2AuthorizationRequest authRequest = TestOAuth2AuthorizationRequests.request().attributes(attributes)
				.build();
		when(this.authorizationRequestRepository.removeAuthorizationRequest(any(), any())).thenReturn(authRequest);

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("code", "code123");
		params.add("state", authRequest.getState());
		this.mvc.perform(get("/login/oauth2/code/google").params(params));

		// assertions
		verify(authenticationSuccessListener).onApplicationEvent(any(AuthenticationSuccessEvent.class));
	}

	@Test
	public void requestWhenOidcAuthenticationResponseValidThenJwtDecoderFactoryCalled() throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration-WithJwtDecoderFactoryAndDefaultSuccessHandler"))
				.autowire();
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(OidcParameterNames.ID_TOKEN, "token123");
		OAuth2AccessTokenResponse accessTokenResponse = accessTokenResponse().additionalParameters(additionalParameters)
				.build();
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);

		Jwt jwt = TestJwts.user();
		when(this.jwtDecoderFactory.createDecoder(any())).thenReturn(token -> jwt);

		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2ParameterNames.REGISTRATION_ID, "google-login");
		OAuth2AuthorizationRequest authRequest = TestOAuth2AuthorizationRequests.request().attributes(attributes)
				.scope("openid").build();
		when(this.authorizationRequestRepository.removeAuthorizationRequest(any(), any())).thenReturn(authRequest);

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("code", "code123");
		params.add("state", authRequest.getState());
		this.mvc.perform(get("/login/oauth2/code/google").params(params)).andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("/"));
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Test
	public void requestWhenCustomGrantedAuthoritiesMapperThenCalled() throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration-WithCustomGrantedAuthorities")).autowire();
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(OidcParameterNames.ID_TOKEN, "token123");
		OAuth2AccessTokenResponse accessTokenResponse = accessTokenResponse().additionalParameters(additionalParameters)
				.build();
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);

		OAuth2User oauth2User = TestOAuth2Users.create();
		when(this.oauth2UserService.loadUser(any())).thenReturn(oauth2User);

		GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_OAUTH2_USER");
		when(this.grantedAuthoritiesMapper.mapAuthorities(any()))
				.thenReturn((Collection) Collections.singletonList(grantedAuthority));

		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2ParameterNames.REGISTRATION_ID, "google-login");
		OAuth2AuthorizationRequest authRequest = TestOAuth2AuthorizationRequests.request().attributes(attributes)
				.build();
		when(this.authorizationRequestRepository.removeAuthorizationRequest(any(), any())).thenReturn(authRequest);

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("code", "code123");
		params.add("state", authRequest.getState());
		this.mvc.perform(get("/login/oauth2/code/google").params(params)).andExpect(status().is2xxSuccessful());

		ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);
		verify(authenticationSuccessHandler).onAuthenticationSuccess(any(), any(), authenticationCaptor.capture());
		Authentication authenticationValue = authenticationCaptor.getValue();
		assertThat(authenticationValue.getAuthorities()).hasSize(1);
		assertThat(authenticationValue.getAuthorities()).first().isInstanceOf(SimpleGrantedAuthority.class)
				.hasToString("ROLE_OAUTH2_USER");

		// re-setup for OIDC test
		Jwt jwt = TestJwts.user();
		when(this.jwtDecoderFactory.createDecoder(any())).thenReturn(token -> jwt);

		grantedAuthority = new SimpleGrantedAuthority("ROLE_OIDC_USER");
		when(this.grantedAuthoritiesMapper.mapAuthorities(any()))
				.thenReturn((Collection) Collections.singletonList(grantedAuthority));

		authRequest = TestOAuth2AuthorizationRequests.request().attributes(attributes).scope("openid").build();
		when(this.authorizationRequestRepository.removeAuthorizationRequest(any(), any())).thenReturn(authRequest);

		this.mvc.perform(get("/login/oauth2/code/google").params(params)).andExpect(status().is2xxSuccessful());

		authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);
		verify(authenticationSuccessHandler, times(2)).onAuthenticationSuccess(any(), any(),
				authenticationCaptor.capture());
		authenticationValue = authenticationCaptor.getValue();
		assertThat(authenticationValue.getAuthorities()).hasSize(1);
		assertThat(authenticationValue.getAuthorities()).first().isInstanceOf(SimpleGrantedAuthority.class)
				.hasToString("ROLE_OIDC_USER");
	}

	@SuppressWarnings({ "unchecked", "rawtypes" })
	@Test
	public void successOidcLoginWhenSingleClientRegistrationAndCustomAuthoritiesThenReturnSuccessWithCorrectAuthorities()
			throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration-WithJwtDecoderFactory")).autowire();
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put(OidcParameterNames.ID_TOKEN, "token123");
		OAuth2AccessTokenResponse accessTokenResponse = accessTokenResponse().additionalParameters(additionalParameters)
				.build();
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);

		Jwt jwt = TestJwts.user();
		when(this.jwtDecoderFactory.createDecoder(any())).thenReturn(token -> jwt);

		GrantedAuthority grantedAuthority = new SimpleGrantedAuthority("ROLE_OIDC_USER");
		when(this.grantedAuthoritiesMapper.mapAuthorities(any()))
				.thenReturn((Collection) Collections.singletonList(grantedAuthority));

		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2ParameterNames.REGISTRATION_ID, "google-login");
		OAuth2AuthorizationRequest authRequest = TestOAuth2AuthorizationRequests.request().attributes(attributes)
				.scope("openid").build();
		when(this.authorizationRequestRepository.removeAuthorizationRequest(any(), any())).thenReturn(authRequest);

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("code", "code123");
		params.add("state", authRequest.getState());
		this.mvc.perform(get("/login/oauth2/code/google").params(params)).andExpect(status().is2xxSuccessful());

		ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);
		verify(authenticationSuccessHandler).onAuthenticationSuccess(any(), any(), authenticationCaptor.capture());
		Authentication authenticationValue = authenticationCaptor.getValue();
		assertThat(authenticationValue.getAuthorities()).hasSize(1);
		assertThat(authenticationValue.getAuthorities()).first().isInstanceOf(SimpleGrantedAuthority.class)
				.hasToString("ROLE_OIDC_USER");
	}

	// gh-5488
	@Test
	public void requestWhenCustomLoginProcessingUrlThenProcessAuthentication() throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration-WithCustomLoginProcessingUrl")).autowire();
		OAuth2AccessTokenResponse accessTokenResponse = accessTokenResponse().build();
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);

		OAuth2User oauth2User = TestOAuth2Users.create();
		when(this.oauth2UserService.loadUser(any())).thenReturn(oauth2User);

		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2ParameterNames.REGISTRATION_ID, "google-login");
		OAuth2AuthorizationRequest authRequest = TestOAuth2AuthorizationRequests.request().attributes(attributes)
				.build();
		when(this.authorizationRequestRepository.removeAuthorizationRequest(any(), any())).thenReturn(authRequest);

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("code", "code123");
		params.add("state", authRequest.getState());
		this.mvc.perform(get("/login/oauth2/google").params(params)).andExpect(status().is2xxSuccessful());

		ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);
		verify(authenticationSuccessHandler).onAuthenticationSuccess(any(), any(), authenticationCaptor.capture());
		Authentication authenticationValue = authenticationCaptor.getValue();
		assertThat(authenticationValue.getAuthorities()).hasSize(1);
		assertThat(authenticationValue.getAuthorities()).first().isInstanceOf(SimpleGrantedAuthority.class)
				.hasToString("ROLE_USER");
	}

	// gh-5521
	@Test
	public void requestWhenCustomAuthorizationRequestResolverThenCalled() throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration-WithCustomAuthorizationRequestResolver"))
				.autowire();

		this.mvc.perform(get("/oauth2/authorization/google")).andExpect(status().is3xxRedirection());

		verify(oauth2AuthorizationRequestResolver).resolve(any());
	}

	// gh-5347
	@Test
	public void requestWhenMultipleClientsConfiguredThenRedirectDefaultLoginPage() throws Exception {
		this.spring.configLocations(this.xml("MultiClientRegistration")).autowire();

		this.mvc.perform(get("/")).andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("http://localhost/login"));
	}

	@Test
	public void requestWhenCustomLoginPageThenRedirectCustomLoginPage() throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration-WithCustomLoginPage")).autowire();

		this.mvc.perform(get("/")).andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("http://localhost/custom-login"));
	}

	// gh-6802
	@Test
	public void requestWhenSingleClientRegistrationAndFormLoginConfiguredThenRedirectDefaultLoginPage()
			throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration-WithFormLogin")).autowire();

		this.mvc.perform(get("/")).andExpect(status().is3xxRedirection())
				.andExpect(redirectedUrl("http://localhost/login"));
	}

	@Test
	public void requestWhenCustomClientRegistrationRepositoryThenCalled() throws Exception {
		this.spring.configLocations(this.xml("WithCustomClientRegistrationRepository")).autowire();

		OAuth2AccessTokenResponse accessTokenResponse = accessTokenResponse().build();
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);

		OAuth2User oauth2User = TestOAuth2Users.create();
		when(this.oauth2UserService.loadUser(any())).thenReturn(oauth2User);

		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2ParameterNames.REGISTRATION_ID, "google-login");
		OAuth2AuthorizationRequest authRequest = TestOAuth2AuthorizationRequests.request().attributes(attributes)
				.build();
		when(this.authorizationRequestRepository.removeAuthorizationRequest(any(), any())).thenReturn(authRequest);

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("code", "code123");
		params.add("state", authRequest.getState());
		this.mvc.perform(get("/login/oauth2/code/google").params(params));

		assertThat(MockUtil.isMock(clientRegistrationRepository)).isTrue();
		verify(clientRegistrationRepository).findByRegistrationId("google-login");

		Field field = oauth2LoginAuthenticationFilter.getClass().getDeclaredField("clientRegistrationRepository");
		field.setAccessible(true);
		Object fieldVal = field.get(oauth2LoginAuthenticationFilter);
		assertThat(MockUtil.isMock(fieldVal)).isTrue();
		assertThat(fieldVal).isSameAs(clientRegistrationRepository);
	}

	@Test
	public void requestWhenCustomAuthorizedClientRepositoryThenCalled() throws Exception {
		this.spring.configLocations(this.xml("WithCustomAuthorizedClientRepository")).autowire();

		ClientRegistration clientReg = TestClientRegistrations.clientRegistration().build();
		when(this.clientRegistrationRepository.findByRegistrationId(any())).thenReturn(clientReg);

		OAuth2AccessTokenResponse accessTokenResponse = accessTokenResponse().build();
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);

		OAuth2User oauth2User = TestOAuth2Users.create();
		when(this.oauth2UserService.loadUser(any())).thenReturn(oauth2User);

		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2ParameterNames.REGISTRATION_ID, "google-login");
		OAuth2AuthorizationRequest authRequest = TestOAuth2AuthorizationRequests.request().attributes(attributes)
				.build();
		when(this.authorizationRequestRepository.removeAuthorizationRequest(any(), any())).thenReturn(authRequest);

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("code", "code123");
		params.add("state", authRequest.getState());
		this.mvc.perform(get("/login/oauth2/code/registration-id").params(params));

		assertThat(MockUtil.isMock(oauth2AuthorizedClientRepository)).isTrue();
		verify(oauth2AuthorizedClientRepository).saveAuthorizedClient(any(), any(), any(), any());

		Field field = oauth2LoginAuthenticationFilter.getClass().getDeclaredField("authorizedClientRepository");
		field.setAccessible(true);
		Object fieldVal = field.get(oauth2LoginAuthenticationFilter);
		assertThat(MockUtil.isMock(fieldVal)).isTrue();
		assertThat(fieldVal).isSameAs(oauth2AuthorizedClientRepository);
	}

	@Test
	public void requestWhenCustomAuthorizedClientServiceThenCalled() throws Exception {
		this.spring.configLocations(this.xml("WithCustomAuthorizedClientService")).autowire();

		ClientRegistration clientReg = TestClientRegistrations.clientRegistration().build();
		when(this.clientRegistrationRepository.findByRegistrationId(any())).thenReturn(clientReg);

		OAuth2AccessTokenResponse accessTokenResponse = accessTokenResponse().build();
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);

		OAuth2User oauth2User = TestOAuth2Users.create();
		when(this.oauth2UserService.loadUser(any())).thenReturn(oauth2User);

		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2ParameterNames.REGISTRATION_ID, "google-login");
		OAuth2AuthorizationRequest authRequest = TestOAuth2AuthorizationRequests.request().attributes(attributes)
				.build();
		when(this.authorizationRequestRepository.removeAuthorizationRequest(any(), any())).thenReturn(authRequest);

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("code", "code123");
		params.add("state", authRequest.getState());
		this.mvc.perform(get("/login/oauth2/code/registration-id").params(params));

		assertThat(MockUtil.isMock(oauth2AuthorizedClientService)).isTrue();
		verify(oauth2AuthorizedClientService).saveAuthorizedClient(any(), any());

		Field authorizedClientRepositoryField = oauth2LoginAuthenticationFilter.getClass()
				.getDeclaredField("authorizedClientRepository");
		authorizedClientRepositoryField.setAccessible(true);
		Object authorizedClientRepositoryFieldVal = authorizedClientRepositoryField
				.get(oauth2LoginAuthenticationFilter);
		assertThat(authorizedClientRepositoryFieldVal)
				.isInstanceOf(AuthenticatedPrincipalOAuth2AuthorizedClientRepository.class);

		Field authorizedClientServiceField = authorizedClientRepositoryFieldVal.getClass()
				.getDeclaredField("authorizedClientService");
		authorizedClientServiceField.setAccessible(true);
		Object authorizedClientServiceFieldVal = authorizedClientServiceField.get(authorizedClientRepositoryFieldVal);
		assertThat(MockUtil.isMock(authorizedClientServiceFieldVal)).isTrue();
		assertThat(authorizedClientServiceFieldVal).isSameAs(oauth2AuthorizedClientService);
	}

	@Test
	public void requestWhenCustomAuthorizationRequestRepositoryThenCalled() throws Exception {
		this.spring.configLocations(this.xml("WithCustomAuthorizationRequestRepository")).autowire();

		ClientRegistration clientReg = TestClientRegistrations.clientRegistration().build();
		when(this.clientRegistrationRepository.findByRegistrationId(any())).thenReturn(clientReg);

		OAuth2AccessTokenResponse accessTokenResponse = accessTokenResponse().build();
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);

		OAuth2User oauth2User = TestOAuth2Users.create();
		when(this.oauth2UserService.loadUser(any())).thenReturn(oauth2User);

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("code", "code123");
		params.add("state", "state");
		this.mvc.perform(get("/login/oauth2/code/registration-id").params(params));

		assertThat(MockUtil.isMock(authorizationRequestRepository)).isTrue();
		verify(authorizationRequestRepository).removeAuthorizationRequest(any(), any());

		Field authorizationRequestRepositoryField = oauth2LoginAuthenticationFilter.getClass()
				.getDeclaredField("authorizationRequestRepository");
		authorizationRequestRepositoryField.setAccessible(true);
		Object authorizationRequestRepositoryFieldVal = authorizationRequestRepositoryField
				.get(oauth2LoginAuthenticationFilter);
		assertThat(MockUtil.isMock(authorizationRequestRepositoryFieldVal)).isTrue();
		assertThat(authorizationRequestRepositoryFieldVal).isSameAs(authorizationRequestRepository);
	}

	@Test
	public void requestWhenCustomAuthenticationSuccessHandlerThenCalled() throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration-WithCustomAuthenticationHandler")).autowire();
		OAuth2AccessTokenResponse accessTokenResponse = accessTokenResponse().build();
		when(this.accessTokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);

		OAuth2User oauth2User = TestOAuth2Users.create();
		when(this.oauth2UserService.loadUser(any())).thenReturn(oauth2User);

		Map<String, Object> attributes = new HashMap<>();
		attributes.put(OAuth2ParameterNames.REGISTRATION_ID, "google-login");
		OAuth2AuthorizationRequest authRequest = TestOAuth2AuthorizationRequests.request().attributes(attributes)
				.build();
		when(this.authorizationRequestRepository.removeAuthorizationRequest(any(), any())).thenReturn(authRequest);

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("code", "code123");
		params.add("state", authRequest.getState());
		this.mvc.perform(get("/login/oauth2/code/google").params(params)).andExpect(status().is2xxSuccessful());

		ArgumentCaptor<Authentication> authenticationCaptor = ArgumentCaptor.forClass(Authentication.class);
		verify(authenticationSuccessHandler).onAuthenticationSuccess(any(), any(), authenticationCaptor.capture());
		Authentication authenticationValue = authenticationCaptor.getValue();
		assertThat(authenticationValue.getAuthorities()).hasSize(1);
		assertThat(authenticationValue.getAuthorities()).first().isInstanceOf(SimpleGrantedAuthority.class)
				.hasToString("ROLE_USER");

	}

	@Test
	public void requestWhenCustomAuthenticationFailureHandlerThenCalled() throws Exception {
		this.spring.configLocations(this.xml("SingleClientRegistration-WithCustomAuthenticationHandler")).autowire();

		MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
		params.add("code", "code123");
		params.add("state", "state123");
		this.mvc.perform(get("/login/oauth2/code/google").params(params)).andExpect(status().isIAmATeapot());
	}

	private String xml(String configName) {
		return CONFIG_LOCATION_PREFIX + "-" + configName + ".xml";
	}

	public static class TeapotAuthenticationHandler
			implements AuthenticationSuccessHandler, AuthenticationFailureHandler {

		@Override
		public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
				AuthenticationException exception) {
			response.setStatus(HttpStatus.I_AM_A_TEAPOT.value());
		}

		@Override
		public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
				Authentication authentication) {
			response.setStatus(HttpStatus.I_AM_A_TEAPOT.value());
		}
	}

}
