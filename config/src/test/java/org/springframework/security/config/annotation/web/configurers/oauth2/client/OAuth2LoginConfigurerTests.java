/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.config.annotation.web.configurers.oauth2.client;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.PropertyAccessorFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.oauth2.client.CommonOAuth2Provider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
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
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link OAuth2LoginConfigurer}.
 *
 * @author Kazuki Shimizu
 * @since 5.0.1
 */
public class OAuth2LoginConfigurerTests {

	private static final ClientRegistration CLIENT_REGISTRATION = CommonOAuth2Provider.GOOGLE
			.getBuilder("google").clientId("clientId").clientSecret("clientSecret")
			.build();

	private ConfigurableApplicationContext context;

	@Autowired
	private FilterChainProxy springSecurityFilterChain;

	@Autowired
	private AuthorizationRequestRepository<OAuth2AuthorizationRequest> authorizationRequestRepository;

	@Autowired
	SecurityContextRepository securityContextRepository;

	private MockHttpServletRequest request;
	private MockHttpServletResponse response;
	private MockFilterChain filterChain;

	@Before
	public void setup() {
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.filterChain = new MockFilterChain();

		this.request.setMethod("GET");
		this.request.setServletPath("/login/oauth2/code/google");
	}

	@After
	public void cleanup() {
		if (this.context != null) {
			this.context.close();
		}
	}

	@Test
	public void oauth2Login() throws Exception {
		// setup application context
		loadConfig(OAuth2LoginConfig.class);

		// setup authorization request
		OAuth2AuthorizationRequest authorizationRequest = createOAuth2AuthorizationRequest();
		this.authorizationRequestRepository.saveAuthorizationRequest(
			authorizationRequest, this.request, this.response);

		// setup authentication parameters
		this.request.setParameter("code", "code123");
		this.request.setParameter("state", authorizationRequest.getState());

		// perform test
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);

		// assertions
		Authentication authentication = this.securityContextRepository
				.loadContext(new HttpRequestResponseHolder(this.request, this.response))
				.getAuthentication();
		assertThat(authentication.getAuthorities()).hasSize(1);
		assertThat(authentication.getAuthorities()).first()
				.isInstanceOf(OAuth2UserAuthority.class).hasToString("ROLE_USER");
	}

	// gh-6009
	@Test
	public void oauth2LoginWhenSuccessThenAuthenticationSuccessEventPublished() throws Exception {
		// setup application context
		loadConfig(OAuth2LoginConfig.class);

		// setup authorization request
		OAuth2AuthorizationRequest authorizationRequest = createOAuth2AuthorizationRequest();
		this.authorizationRequestRepository.saveAuthorizationRequest(
				authorizationRequest, this.request, this.response);

		// setup authentication parameters
		this.request.setParameter("code", "code123");
		this.request.setParameter("state", authorizationRequest.getState());

		// perform test
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);

		// assertions
		assertThat(OAuth2LoginConfig.EVENTS).isNotEmpty();
		assertThat(OAuth2LoginConfig.EVENTS).hasSize(1);
		assertThat(OAuth2LoginConfig.EVENTS.get(0)).isInstanceOf(AuthenticationSuccessEvent.class);
	}

	@Test
	public void oauth2LoginCustomWithConfigurer() throws Exception {
		// setup application context
		loadConfig(OAuth2LoginConfigCustomWithConfigurer.class);

		// setup authorization request
		OAuth2AuthorizationRequest authorizationRequest = createOAuth2AuthorizationRequest();
		this.authorizationRequestRepository.saveAuthorizationRequest(
			authorizationRequest, this.request, this.response);

		// setup authentication parameters
		this.request.setParameter("code", "code123");
		this.request.setParameter("state", authorizationRequest.getState());

		// perform test
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);

		// assertions
		Authentication authentication = this.securityContextRepository
				.loadContext(new HttpRequestResponseHolder(this.request, this.response))
				.getAuthentication();
		assertThat(authentication.getAuthorities()).hasSize(2);
		assertThat(authentication.getAuthorities()).first().hasToString("ROLE_USER");
		assertThat(authentication.getAuthorities()).last().hasToString("ROLE_OAUTH2_USER");
	}

	@Test
	public void oauth2LoginCustomWithBeanRegistration() throws Exception {
		// setup application context
		loadConfig(OAuth2LoginConfigCustomWithBeanRegistration.class);

		// setup authorization request
		OAuth2AuthorizationRequest authorizationRequest = createOAuth2AuthorizationRequest();
		this.authorizationRequestRepository.saveAuthorizationRequest(
			authorizationRequest, this.request, this.response);

		// setup authentication parameters
		this.request.setParameter("code", "code123");
		this.request.setParameter("state", authorizationRequest.getState());

		// perform test
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);

		// assertions
		Authentication authentication = this.securityContextRepository
				.loadContext(new HttpRequestResponseHolder(this.request, this.response))
				.getAuthentication();
		assertThat(authentication.getAuthorities()).hasSize(2);
		assertThat(authentication.getAuthorities()).first().hasToString("ROLE_USER");
		assertThat(authentication.getAuthorities()).last().hasToString("ROLE_OAUTH2_USER");
	}

	// gh-5488
	@Test
	public void oauth2LoginConfigLoginProcessingUrl() throws Exception {
		// setup application context
		loadConfig(OAuth2LoginConfigLoginProcessingUrl.class);

		// setup authorization request
		OAuth2AuthorizationRequest authorizationRequest = createOAuth2AuthorizationRequest();
		this.request.setServletPath("/login/oauth2/google");
		this.authorizationRequestRepository.saveAuthorizationRequest(
				authorizationRequest, this.request, this.response);

		// setup authentication parameters
		this.request.setParameter("code", "code123");
		this.request.setParameter("state", authorizationRequest.getState());

		// perform test
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);

		// assertions
		Authentication authentication = this.securityContextRepository
				.loadContext(new HttpRequestResponseHolder(this.request, this.response))
				.getAuthentication();
		assertThat(authentication.getAuthorities()).hasSize(1);
		assertThat(authentication.getAuthorities()).first()
				.isInstanceOf(OAuth2UserAuthority.class).hasToString("ROLE_USER");
	}

	@Test
	public void oidcLogin() throws Exception {
		// setup application context
		loadConfig(OAuth2LoginConfig.class);
		registerJwtDecoder();

		// setup authorization request
		OAuth2AuthorizationRequest authorizationRequest = createOAuth2AuthorizationRequest("openid");
		this.authorizationRequestRepository.saveAuthorizationRequest(
			authorizationRequest, this.request, this.response);

		// setup authentication parameters
		this.request.setParameter("code", "code123");
		this.request.setParameter("state", authorizationRequest.getState());

		// perform test
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);

		// assertions
		Authentication authentication = this.securityContextRepository
				.loadContext(new HttpRequestResponseHolder(this.request, this.response))
				.getAuthentication();
		assertThat(authentication.getAuthorities()).hasSize(1);
		assertThat(authentication.getAuthorities()).first()
				.isInstanceOf(OidcUserAuthority.class).hasToString("ROLE_USER");
	}

	@Test
	public void oidcLoginCustomWithConfigurer() throws Exception {
		// setup application context
		loadConfig(OAuth2LoginConfigCustomWithConfigurer.class);
		registerJwtDecoder();

		// setup authorization request
		OAuth2AuthorizationRequest authorizationRequest = createOAuth2AuthorizationRequest("openid");
		this.authorizationRequestRepository.saveAuthorizationRequest(
			authorizationRequest, this.request, this.response);

		// setup authentication parameters
		this.request.setParameter("code", "code123");
		this.request.setParameter("state", authorizationRequest.getState());

		// perform test
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);

		// assertions
		Authentication authentication = this.securityContextRepository
				.loadContext(new HttpRequestResponseHolder(this.request, this.response))
				.getAuthentication();
		assertThat(authentication.getAuthorities()).hasSize(2);
		assertThat(authentication.getAuthorities()).first().hasToString("ROLE_USER");
		assertThat(authentication.getAuthorities()).last().hasToString("ROLE_OIDC_USER");
	}

	@Test
	public void oidcLoginCustomWithBeanRegistration() throws Exception {
		// setup application context
		loadConfig(OAuth2LoginConfigCustomWithBeanRegistration.class);
		registerJwtDecoder();

		// setup authorization request
		OAuth2AuthorizationRequest authorizationRequest = createOAuth2AuthorizationRequest("openid");
		this.authorizationRequestRepository.saveAuthorizationRequest(
			authorizationRequest, this.request, this.response);

		// setup authentication parameters
		this.request.setParameter("code", "code123");
		this.request.setParameter("state", authorizationRequest.getState());

		// perform test
		this.springSecurityFilterChain.doFilter(this.request, this.response, this.filterChain);

		// assertions
		Authentication authentication = this.securityContextRepository
				.loadContext(new HttpRequestResponseHolder(this.request, this.response))
				.getAuthentication();
		assertThat(authentication.getAuthorities()).hasSize(2);
		assertThat(authentication.getAuthorities()).first().hasToString("ROLE_USER");
		assertThat(authentication.getAuthorities()).last().hasToString("ROLE_OIDC_USER");
	}

	private void loadConfig(Class<?>... configs) {
		AnnotationConfigWebApplicationContext applicationContext = new AnnotationConfigWebApplicationContext();
		applicationContext.register(configs);
		applicationContext.refresh();
		applicationContext.getAutowireCapableBeanFactory().autowireBean(this);
		this.context = applicationContext;
	}

	private void registerJwtDecoder() {
		JwtDecoder decoder = token -> {
			Map<String, Object> claims = new HashMap<>();
			claims.put(IdTokenClaimNames.SUB, "sub123");
			claims.put(IdTokenClaimNames.ISS, "http://localhost/iss");
			claims.put(IdTokenClaimNames.AUD, Arrays.asList("clientId", "a", "u", "d"));
			claims.put(IdTokenClaimNames.AZP, "clientId");
			return new Jwt("token123", Instant.now(), Instant.now().plusSeconds(3600),
					Collections.singletonMap("header1", "value1"), claims);
		};
		this.springSecurityFilterChain.getFilters("/login/oauth2/code/google").stream()
				.filter(OAuth2LoginAuthenticationFilter.class::isInstance)
				.findFirst()
				.ifPresent(filter -> PropertyAccessorFactory.forDirectFieldAccess(filter)
					.setPropertyValue(
						"authenticationManager.providers[2].jwtDecoders['google']",
						decoder));
	}

	private OAuth2AuthorizationRequest createOAuth2AuthorizationRequest(String... scopes) {
		return OAuth2AuthorizationRequest.authorizationCode()
				.authorizationUri(CLIENT_REGISTRATION.getProviderDetails().getAuthorizationUri())
				.clientId(CLIENT_REGISTRATION.getClientId())
				.state("state123")
				.redirectUri("http://localhost")
				.additionalParameters(
					Collections.singletonMap(
						OAuth2ParameterNames.REGISTRATION_ID,
						CLIENT_REGISTRATION.getRegistrationId()))
				.scope(scopes)
				.build();
	}

	@EnableWebSecurity
	static class OAuth2LoginConfig extends CommonWebSecurityConfigurerAdapter implements ApplicationListener<AuthenticationSuccessEvent> {
		static List<AuthenticationSuccessEvent> EVENTS = new ArrayList<>();

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.oauth2Login()
					.clientRegistrationRepository(
						new InMemoryClientRegistrationRepository(CLIENT_REGISTRATION));
			super.configure(http);
		}

		@Override
		public void onApplicationEvent(AuthenticationSuccessEvent event) {
			EVENTS.add(event);
		}
	}

	@EnableWebSecurity
	static class OAuth2LoginConfigCustomWithConfigurer extends CommonWebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.oauth2Login()
					.clientRegistrationRepository(
							new InMemoryClientRegistrationRepository(CLIENT_REGISTRATION))
					.userInfoEndpoint()
						.userAuthoritiesMapper(createGrantedAuthoritiesMapper());
			super.configure(http);
		}
	}

	@EnableWebSecurity
	static class OAuth2LoginConfigCustomWithBeanRegistration extends CommonWebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.oauth2Login();
			super.configure(http);
		}

		@Bean
		ClientRegistrationRepository clientRegistrationRepository() {
			return new InMemoryClientRegistrationRepository(CLIENT_REGISTRATION);
		}

		@Bean
		GrantedAuthoritiesMapper grantedAuthoritiesMapper() {
			return createGrantedAuthoritiesMapper();
		}
	}

	@EnableWebSecurity
	static class OAuth2LoginConfigLoginProcessingUrl extends CommonWebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.oauth2Login()
					.clientRegistrationRepository(
						new InMemoryClientRegistrationRepository(CLIENT_REGISTRATION))
					.loginProcessingUrl("/login/oauth2/*");
			super.configure(http);
		}
	}

	private static abstract class CommonWebSecurityConfigurerAdapter extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.securityContext()
					.securityContextRepository(securityContextRepository())
					.and()
				.oauth2Login()
					.tokenEndpoint()
						.accessTokenResponseClient(createOauth2AccessTokenResponseClient())
						.and()
					.userInfoEndpoint()
						.userService(createOauth2UserService())
						.oidcUserService(createOidcUserService());
		}

		@Bean
		SecurityContextRepository securityContextRepository() {
			return new HttpSessionSecurityContextRepository();
		}

		@Bean
		HttpSessionOAuth2AuthorizationRequestRepository oauth2AuthorizationRequestRepository() {
			return new HttpSessionOAuth2AuthorizationRequestRepository();
		}
	}

	private static OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> createOauth2AccessTokenResponseClient() {
		return request -> {
			Map<String, Object> additionalParameters = new HashMap<>();
			if (request.getAuthorizationExchange().getAuthorizationRequest().getScopes().contains("openid")) {
				additionalParameters.put(OidcParameterNames.ID_TOKEN, "token123");
			}
			return OAuth2AccessTokenResponse.withToken("accessToken123")
						.tokenType(OAuth2AccessToken.TokenType.BEARER)
						.additionalParameters(additionalParameters)
						.build();
		};
	}

	private static OAuth2UserService<OAuth2UserRequest, OAuth2User> createOauth2UserService() {
		Map<String, Object> userAttributes = Collections.singletonMap("name", "spring");
		return request -> new DefaultOAuth2User(
				Collections.singleton(new OAuth2UserAuthority(userAttributes)),
				userAttributes, "name");
	}

	private static OAuth2UserService<OidcUserRequest, OidcUser> createOidcUserService() {
		OidcIdToken idToken = new OidcIdToken("token123", Instant.now(),
			Instant.now().plusSeconds(3600), Collections.singletonMap(IdTokenClaimNames.SUB, "sub123"));
		return request -> new DefaultOidcUser(
				Collections.singleton(new OidcUserAuthority(idToken)), idToken);
	}

	private static GrantedAuthoritiesMapper createGrantedAuthoritiesMapper() {
		return authorities -> {
			boolean isOidc = OidcUserAuthority.class
					.isInstance(authorities.iterator().next());
			List<GrantedAuthority> mappedAuthorities = new ArrayList<>(authorities);
			mappedAuthorities.add(new SimpleGrantedAuthority(
					isOidc ? "ROLE_OIDC_USER" : "ROLE_OAUTH2_USER"));
			return mappedAuthorities;
		};
	}
}
