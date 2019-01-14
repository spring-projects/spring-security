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
package org.springframework.security.samples;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebResponse;
import com.gargoylesoftware.htmlunit.html.DomNodeList;
import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlElement;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.InMemoryReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.ReactiveOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginReactiveAuthenticationManager;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.ReactiveOAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.web.server.AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.server.ServerOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.util.*;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Integration tests for the OAuth 2.0 login in a web-flux environment.
 *
 * @author Arjun Curat
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
public class OAuth2LoginApplicationTests {

	private static final String AUTHORIZATION_BASE_URI = "/oauth2/authorization";
	private static final String AUTHORIZE_BASE_URL = "http://localhost:%d/login/oauth2/code";
	private static final String LOCALHOST_URL = "http://localhost:";

	@LocalServerPort
	int port;

	WebClient webClient = new WebClient();

	@Autowired
	private ReactiveClientRegistrationRepository clientRegistrationRepository;

	@Test
	public void requestIndexPageWhenNotAuthenticatedThenDisplayLoginPage() throws Exception {
		HtmlPage page = this.webClient.getPage(getUrl("/"));
		this.assertLoginPage(page);
	}

	@Test
	public void requestOtherPageWhenNotAuthenticatedThenDisplayLoginPage() throws Exception {
		HtmlPage page = this.webClient.getPage(getUrl("/other-page"));
		this.assertLoginPage(page);
	}

	@Test
	public void requestAuthorizationCodeGrantWhenValidAuthorizationResponseThenDisplayIndexPage() throws Exception {
		HtmlPage page = this.webClient.getPage(getUrl("/"));

		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId("github").block();

		HtmlAnchor clientAnchorElement = this.getClientAnchorElement(page, clientRegistration);
		assertThat(clientAnchorElement).isNotNull();

		WebResponse response = this.followLinkDisableRedirects(clientAnchorElement);

		UriComponents authorizeRequestUriComponents = UriComponentsBuilder.fromUri(
				URI.create(response.getResponseHeaderValue("Location"))).build();

		Map<String, String> params = authorizeRequestUriComponents.getQueryParams().toSingleValueMap();
		String code = "auth-code";
		String state = URLDecoder.decode(params.get(OAuth2ParameterNames.STATE), "UTF-8");
		String redirectUri = URLDecoder.decode(params.get(OAuth2ParameterNames.REDIRECT_URI), "UTF-8");

		String authorizationResponseUri =
				getAuthorizationResponseUri(code, state, redirectUri);

		page = this.webClient.getPage(new URL(authorizationResponseUri));
		this.assertIndexPage(page);
	}

	@Test
	public void requestAuthorizationCodeGrantWhenNoMatchingAuthorizationRequestThenDisplayLoginPageWithError() throws Exception {
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId("google").block();

		String code = "auth-code";
		String state = "state";
		String redirectUri = String.format(AUTHORIZE_BASE_URL, port) + "/" + clientRegistration.getRegistrationId();

		String authorizationResponseUri =
				getAuthorizationResponseUri(code, state, redirectUri);

		// Clear session cookie will ensure the 'session-saved'
		// Authorization Request (from previous request) is not found
		this.webClient.getCookieManager().clearCookies();

		WebResponse response = null;
		try {
			this.webClient.getPage(new URL(authorizationResponseUri));
		} catch (FailingHttpStatusCodeException ex) {
			response = ex.getResponse();
		}
		assertThat(response.getStatusCode()).isEqualTo(500);
		assertThat(response.getContentAsString()).contains("authorization_request_not_found");
	}

	@Test
	public void requestAuthorizeClientWhenInvalidClientThenStatusInternalServerError() throws Exception {
		HtmlPage page = this.webClient.getPage(getUrl("/"));

		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId("google").block();

		HtmlAnchor clientAnchorElement = this.getClientAnchorElement(page, clientRegistration);
		assertThat(clientAnchorElement).isNotNull();
		clientAnchorElement.setAttribute("href", clientAnchorElement.getHrefAttribute() + "-invalid");

		WebResponse response = null;
		try {
			clientAnchorElement.click();
		} catch (FailingHttpStatusCodeException ex) {
			response = ex.getResponse();
		}

		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST.value());
	}


	@Test
	public void requestAuthorizeGitHubClientWhenLinkClickedThenStatusRedirectForAuthorization() throws Exception {
		HtmlPage page = this.webClient.getPage(getUrl("/"));

		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId("github").block();

		HtmlAnchor clientAnchorElement = this.getClientAnchorElement(page, clientRegistration);
		assertThat(clientAnchorElement).isNotNull();

		WebResponse response = this.followLinkDisableRedirects(clientAnchorElement);

		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FOUND.value());

		String authorizeRedirectUri = response.getResponseHeaderValue("Location");
		assertThat(authorizeRedirectUri).isNotNull();

		UriComponents uriComponents = UriComponentsBuilder.fromUri(URI.create(authorizeRedirectUri)).build();

		String requestUri = uriComponents.getScheme() + "://" + uriComponents.getHost() + uriComponents.getPath();
		assertThat(requestUri).isEqualTo(clientRegistration.getProviderDetails().getAuthorizationUri());

		Map<String, String> params = uriComponents.getQueryParams().toSingleValueMap();

		assertThat(params.get(OAuth2ParameterNames.RESPONSE_TYPE)).isEqualTo(OAuth2AuthorizationResponseType.CODE.getValue());
		assertThat(params.get(OAuth2ParameterNames.CLIENT_ID)).isEqualTo(clientRegistration.getClientId());
		String redirectUri = String.format(AUTHORIZE_BASE_URL, port) + "/" + clientRegistration.getRegistrationId();
		assertThat(URLDecoder.decode(params.get(OAuth2ParameterNames.REDIRECT_URI), "UTF-8")).isEqualTo(redirectUri);
		assertThat(URLDecoder.decode(params.get(OAuth2ParameterNames.SCOPE), "UTF-8"))
				.isEqualTo(clientRegistration.getScopes().stream().collect(Collectors.joining(" ")));
		assertThat(params.get(OAuth2ParameterNames.STATE)).isNotNull();
	}

	@Test
	public void requestAuthorizationCodeGrantWhenInvalidStateParamThenDisplayLoginPageWithError() throws Exception {
		HtmlPage page = this.webClient.getPage(getUrl("/"));
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId("google").block();

		HtmlAnchor clientAnchorElement = this.getClientAnchorElement(page, clientRegistration);
		assertThat(clientAnchorElement).isNotNull();
		this.followLinkDisableRedirects(clientAnchorElement);

		String code = "auth-code";
		String state = "invalid-state";
		String redirectUri = String.format(AUTHORIZE_BASE_URL, port) + "/" + clientRegistration.getRegistrationId();

		String authorizationResponseUri =
				getAuthorizationResponseUri(code, state, redirectUri);

		WebResponse response = null;
		try {
			this.webClient.getPage(new URL(authorizationResponseUri));
		} catch (FailingHttpStatusCodeException ex) {
			response = ex.getResponse();
		}
		assertThat(response.getStatusCode()).isEqualTo(500);
		assertThat(response.getContentAsString()).contains("authorization_request_not_found");
	}

	@Test
	public void requestAuthorizationCodeGrantWhenInvalidRedirectUriThenDisplayLoginPageWithError() throws Exception {
		HtmlPage page = this.webClient.getPage(getUrl("/"));
		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId("google").block();

		HtmlAnchor clientAnchorElement = this.getClientAnchorElement(page, clientRegistration);
		assertThat(clientAnchorElement).isNotNull();

		WebResponse response = this.followLinkDisableRedirects(clientAnchorElement);

		UriComponents authorizeRequestUriComponents = UriComponentsBuilder.fromUri(
				URI.create(response.getResponseHeaderValue("Location"))).build();

		Map<String, String> params = authorizeRequestUriComponents.getQueryParams().toSingleValueMap();
		String code = "auth-code";
		String state = URLDecoder.decode(params.get(OAuth2ParameterNames.STATE), "UTF-8");
		String redirectUri = URLDecoder.decode(params.get(OAuth2ParameterNames.REDIRECT_URI), "UTF-8");
		redirectUri += "-invalid";

		String authorizationResponseUri =
				getAuthorizationResponseUri(code, state, redirectUri);
		try {
			this.webClient.getPage(new URL(authorizationResponseUri));
		} catch (FailingHttpStatusCodeException ex) {
			response = ex.getResponse();
		}
		assertThat(response.getStatusCode()).isEqualTo(500);
		assertThat(response.getContentAsString()).contains("invalid_redirect_uri_parameter");
	}

	private String getAuthorizationResponseUri(String code, String state, String redirectUri) {
		return UriComponentsBuilder.fromHttpUrl(redirectUri)
				.queryParam(OAuth2ParameterNames.CODE, code)
				.queryParam(OAuth2ParameterNames.STATE, state)
				.build().encode().toUriString();
	}

	private String getUrl(String url) {
		return LOCALHOST_URL + port + url;
	}

	private void assertIndexPage(HtmlPage page) throws Exception {
		assertThat(page.getTitleText()).isEqualTo("Spring Security - OAuth 2.0 Login");

		DomNodeList<HtmlElement> divElements = page.getBody().getElementsByTagName("div");
		assertThat(divElements.get(1).asText()).contains("User: acurat");
		assertThat(divElements.get(4).asText()).contains("You are successfully logged in acurat");
	}

	private HtmlAnchor getClientAnchorElement(HtmlPage page, ClientRegistration clientRegistration) {
		Optional<HtmlAnchor> clientAnchorElement = page.getAnchors().stream()
				.filter(e -> e.asText().equals(clientRegistration.getClientName())).findFirst();

		return (clientAnchorElement.orElse(null));
	}

	private WebResponse followLinkDisableRedirects(HtmlAnchor anchorElement) throws Exception {
		WebResponse response = null;
		try {
			// Disable the automatic redirection (which will trigger
			// an exception) so that we can capture the response
			this.webClient.getOptions().setRedirectEnabled(false);
			anchorElement.click();
		} catch (FailingHttpStatusCodeException ex) {
			response = ex.getResponse();
			this.webClient.getOptions().setRedirectEnabled(true);
		}
		return response;
	}

	private void assertLoginPage(HtmlPage page) throws Exception {
		assertThat(page.getTitleText()).isEqualTo("Please sign in");

		int expectedClients = 4;

		List<HtmlAnchor> clientAnchorElements = page.getAnchors();
		assertThat(clientAnchorElements.size()).isEqualTo(expectedClients);

		ClientRegistration googleClientRegistration = this.clientRegistrationRepository.findByRegistrationId("google").block();
		ClientRegistration githubClientRegistration = this.clientRegistrationRepository.findByRegistrationId("github").block();
		ClientRegistration facebookClientRegistration = this.clientRegistrationRepository.findByRegistrationId("facebook").block();
		ClientRegistration oktaClientRegistration = this.clientRegistrationRepository.findByRegistrationId("okta").block();

		String baseAuthorizeUri = AUTHORIZATION_BASE_URI + "/";
		String googleClientAuthorizeUri = baseAuthorizeUri + googleClientRegistration.getRegistrationId();
		String githubClientAuthorizeUri = baseAuthorizeUri + githubClientRegistration.getRegistrationId();
		String facebookClientAuthorizeUri = baseAuthorizeUri + facebookClientRegistration.getRegistrationId();
		String oktaClientAuthorizeUri = baseAuthorizeUri + oktaClientRegistration.getRegistrationId();

		for (int i = 0; i < expectedClients; i++) {
			assertThat(clientAnchorElements.get(i).getAttribute("href")).isIn(
					googleClientAuthorizeUri, githubClientAuthorizeUri,
					facebookClientAuthorizeUri, oktaClientAuthorizeUri);
			assertThat(clientAnchorElements.get(i).asText()).isIn(
					googleClientRegistration.getClientName(),
					githubClientRegistration.getClientName(),
					facebookClientRegistration.getClientName(),
					oktaClientRegistration.getClientName());
		}
	}

	@EnableWebFluxSecurity
	public static class SecurityTestConfig {


		ReactiveOAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> tokenResponseClient =
				mock(ReactiveOAuth2AccessTokenResponseClient.class);

		ReactiveOAuth2UserService<OAuth2UserRequest, OAuth2User> userService = mock(ReactiveOAuth2UserService.class);

		@Bean
		public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {

			http
					.authorizeExchange()
					.anyExchange().authenticated()
					.and()
					.oauth2Login()
					.authenticationManager(authenticationManager());
			return http.build();
		}

		private ReactiveAuthenticationManager authenticationManager() {

			when(tokenResponseClient.getTokenResponse(any())).thenReturn(Mono.just(accessToken()));
			when(userService.loadUser(any())).thenReturn(Mono.just(user()));

			OAuth2LoginReactiveAuthenticationManager oidc =
					new OAuth2LoginReactiveAuthenticationManager(tokenResponseClient, userService);
			return oidc;
		}

		private OAuth2User user() {
			Map<String, Object> attributes = new HashMap<>();
			attributes.put("id", "acurat");
			attributes.put("first-name", "Arjun");
			attributes.put("last-name", "Curat");
			attributes.put("email", "test@mail.com");

			GrantedAuthority authority = new OAuth2UserAuthority(attributes);
			Set<GrantedAuthority> authorities = new HashSet<>();
			authorities.add(authority);

			DefaultOAuth2User user = new DefaultOAuth2User(authorities, attributes, "id");

			return user;
		}

		private OAuth2AccessTokenResponse accessToken() {

			return OAuth2AccessTokenResponse.withToken("access-token-1234")
					.tokenType(OAuth2AccessToken.TokenType.BEARER)
					.expiresIn(60 * 1000)
					.build();
		}

	}


	@SpringBootConfiguration
	@EnableAutoConfiguration
	@ComponentScan(basePackages = "sample.web")
	public static class SpringBootApplicationTestConfig {

		@Bean
		public ReactiveOAuth2AuthorizedClientService authorizedClientService(ReactiveClientRegistrationRepository clientRegistrationRepository) {
			return new InMemoryReactiveOAuth2AuthorizedClientService(clientRegistrationRepository);
		}

		@Bean
		public ServerOAuth2AuthorizedClientRepository authorizedClientRepository(ReactiveOAuth2AuthorizedClientService authorizedClientService) {
			return new AuthenticatedPrincipalServerOAuth2AuthorizedClientRepository(authorizedClientService);

		}
	}

}
