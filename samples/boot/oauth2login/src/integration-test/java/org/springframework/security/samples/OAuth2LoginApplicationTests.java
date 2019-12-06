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
package org.springframework.security.samples;

import com.gargoylesoftware.htmlunit.FailingHttpStatusCodeException;
import com.gargoylesoftware.htmlunit.WebClient;
import com.gargoylesoftware.htmlunit.WebResponse;
import com.gargoylesoftware.htmlunit.html.DomNodeList;
import com.gargoylesoftware.htmlunit.html.HtmlAnchor;
import com.gargoylesoftware.htmlunit.html.HtmlElement;
import com.gargoylesoftware.htmlunit.html.HtmlPage;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.endpoint.OAuth2AccessTokenResponseClient;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.endpoint.OAuth2AccessTokenResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Integration tests for the OAuth 2.0 client filters {@link OAuth2AuthorizationRequestRedirectFilter}
 * and {@link OAuth2LoginAuthenticationFilter}. These filters work together to realize
 * OAuth 2.0 Login leveraging the Authorization Code Grant flow.
 *
 * @author Joe Grandja
 * @since 5.0
 */
@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class OAuth2LoginApplicationTests {
	private static final String AUTHORIZATION_BASE_URI = "/oauth2/authorization";
	private static final String AUTHORIZE_BASE_URL = "http://localhost:8080/login/oauth2/code";

	@Autowired
	private WebClient webClient;

	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;

	@Before
	public void setup() {
		this.webClient.getCookieManager().clearCookies();
	}

	@Test
	public void requestIndexPageWhenNotAuthenticatedThenDisplayLoginPage() throws Exception {
		HtmlPage page = this.webClient.getPage("/");
		this.assertLoginPage(page);
	}

	@Test
	public void requestOtherPageWhenNotAuthenticatedThenDisplayLoginPage() throws Exception {
		HtmlPage page = this.webClient.getPage("/other-page");
		this.assertLoginPage(page);
	}

	@Test
	public void requestAuthorizeGitHubClientWhenLinkClickedThenStatusRedirectForAuthorization() throws Exception {
		HtmlPage page = this.webClient.getPage("/");

		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId("github");

		HtmlAnchor clientAnchorElement = this.getClientAnchorElement(page, clientRegistration);
		assertThat(clientAnchorElement).isNotNull();

		WebResponse response = this.followLinkDisableRedirects(clientAnchorElement);

		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.MOVED_PERMANENTLY.value());

		String authorizeRedirectUri = response.getResponseHeaderValue("Location");
		assertThat(authorizeRedirectUri).isNotNull();

		UriComponents uriComponents = UriComponentsBuilder.fromUri(URI.create(authorizeRedirectUri)).build();

		String requestUri = uriComponents.getScheme() + "://" + uriComponents.getHost() + uriComponents.getPath();
		assertThat(requestUri).isEqualTo(clientRegistration.getProviderDetails().getAuthorizationUri());

		Map<String, String> params = uriComponents.getQueryParams().toSingleValueMap();

		assertThat(params.get(OAuth2ParameterNames.RESPONSE_TYPE)).isEqualTo(OAuth2AuthorizationResponseType.CODE.getValue());
		assertThat(params.get(OAuth2ParameterNames.CLIENT_ID)).isEqualTo(clientRegistration.getClientId());
		String redirectUri = AUTHORIZE_BASE_URL + "/" + clientRegistration.getRegistrationId();
		assertThat(URLDecoder.decode(params.get(OAuth2ParameterNames.REDIRECT_URI), "UTF-8")).isEqualTo(redirectUri);
		assertThat(URLDecoder.decode(params.get(OAuth2ParameterNames.SCOPE), "UTF-8"))
				.isEqualTo(clientRegistration.getScopes().stream().collect(Collectors.joining(" ")));
		assertThat(params.get(OAuth2ParameterNames.STATE)).isNotNull();
	}

	@Test
	public void requestAuthorizeClientWhenInvalidClientThenStatusInternalServerError() throws Exception {
		HtmlPage page = this.webClient.getPage("/");

		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId("google");

		HtmlAnchor clientAnchorElement = this.getClientAnchorElement(page, clientRegistration);
		assertThat(clientAnchorElement).isNotNull();
		clientAnchorElement.setAttribute("href", clientAnchorElement.getHrefAttribute() + "-invalid");

		WebResponse response = null;
		try {
			clientAnchorElement.click();
		} catch (FailingHttpStatusCodeException ex) {
			response = ex.getResponse();
		}

		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.INTERNAL_SERVER_ERROR.value());
	}

	@Test
	public void requestAuthorizationCodeGrantWhenValidAuthorizationResponseThenDisplayIndexPage() throws Exception {
		HtmlPage page = this.webClient.getPage("/");

		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId("github");

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
				UriComponentsBuilder.fromHttpUrl(redirectUri)
						.queryParam(OAuth2ParameterNames.CODE, code)
						.queryParam(OAuth2ParameterNames.STATE, state)
						.build().encode().toUriString();

		page = this.webClient.getPage(new URL(authorizationResponseUri));
		this.assertIndexPage(page);
	}

	@Test
	public void requestAuthorizationCodeGrantWhenNoMatchingAuthorizationRequestThenDisplayLoginPageWithError() throws Exception {
		HtmlPage page = this.webClient.getPage("/");
		URL loginPageUrl = page.getBaseURL();
		URL loginErrorPageUrl = new URL(loginPageUrl.toString() + "?error");

		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId("google");

		String code = "auth-code";
		String state = "state";
		String redirectUri = AUTHORIZE_BASE_URL + "/" + clientRegistration.getRegistrationId();

		String authorizationResponseUri =
				UriComponentsBuilder.fromHttpUrl(redirectUri)
						.queryParam(OAuth2ParameterNames.CODE, code)
						.queryParam(OAuth2ParameterNames.STATE, state)
						.build().encode().toUriString();

		// Clear session cookie will ensure the 'session-saved'
		// Authorization Request (from previous request) is not found
		this.webClient.getCookieManager().clearCookies();

		page = this.webClient.getPage(new URL(authorizationResponseUri));
		assertThat(page.getBaseURL()).isEqualTo(loginErrorPageUrl);

		HtmlElement errorElement = page.getBody().getFirstByXPath("div");
		assertThat(errorElement).isNotNull();
		assertThat(errorElement.asText()).contains("authorization_request_not_found");
	}

	@Test
	public void requestAuthorizationCodeGrantWhenInvalidStateParamThenDisplayLoginPageWithError() throws Exception {
		HtmlPage page = this.webClient.getPage("/");
		URL loginPageUrl = page.getBaseURL();
		URL loginErrorPageUrl = new URL(loginPageUrl.toString() + "?error");

		ClientRegistration clientRegistration = this.clientRegistrationRepository.findByRegistrationId("google");

		HtmlAnchor clientAnchorElement = this.getClientAnchorElement(page, clientRegistration);
		assertThat(clientAnchorElement).isNotNull();
		this.followLinkDisableRedirects(clientAnchorElement);

		String code = "auth-code";
		String state = "invalid-state";
		String redirectUri = AUTHORIZE_BASE_URL + "/" + clientRegistration.getRegistrationId();

		String authorizationResponseUri =
				UriComponentsBuilder.fromHttpUrl(redirectUri)
						.queryParam(OAuth2ParameterNames.CODE, code)
						.queryParam(OAuth2ParameterNames.STATE, state)
						.build().encode().toUriString();

		page = this.webClient.getPage(new URL(authorizationResponseUri));
		assertThat(page.getBaseURL()).isEqualTo(loginErrorPageUrl);

		HtmlElement errorElement = page.getBody().getFirstByXPath("div");
		assertThat(errorElement).isNotNull();
		assertThat(errorElement.asText()).contains("authorization_request_not_found");
	}

	private void assertLoginPage(HtmlPage page) {
		assertThat(page.getTitleText()).isEqualTo("Please sign in");

		int expectedClients = 4;

		List<HtmlAnchor> clientAnchorElements = page.getAnchors();
		assertThat(clientAnchorElements.size()).isEqualTo(expectedClients);

		ClientRegistration googleClientRegistration = this.clientRegistrationRepository.findByRegistrationId("google");
		ClientRegistration githubClientRegistration = this.clientRegistrationRepository.findByRegistrationId("github");
		ClientRegistration facebookClientRegistration = this.clientRegistrationRepository.findByRegistrationId("facebook");
		ClientRegistration oktaClientRegistration = this.clientRegistrationRepository.findByRegistrationId("okta");

		String baseAuthorizeUri = AUTHORIZATION_BASE_URI + "/";
		String googleClientAuthorizeUri = baseAuthorizeUri + googleClientRegistration.getRegistrationId();
		String githubClientAuthorizeUri = baseAuthorizeUri + githubClientRegistration.getRegistrationId();
		String facebookClientAuthorizeUri = baseAuthorizeUri + facebookClientRegistration.getRegistrationId();
		String oktaClientAuthorizeUri = baseAuthorizeUri + oktaClientRegistration.getRegistrationId();

		for (int i=0; i<expectedClients; i++) {
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

	private void assertIndexPage(HtmlPage page) {
		assertThat(page.getTitleText()).isEqualTo("Spring Security - OAuth 2.0 Login");

		DomNodeList<HtmlElement> divElements = page.getBody().getElementsByTagName("div");
		assertThat(divElements.get(1).asText()).contains("User: joeg@springsecurity.io");
		assertThat(divElements.get(4).asText()).contains("You are successfully logged in joeg@springsecurity.io");
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

	@EnableWebSecurity
	public static class SecurityTestConfig extends WebSecurityConfigurerAdapter {

		// @formatter:off
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.authorizeRequests(authorizeRequests ->
					authorizeRequests
						.anyRequest().authenticated()
				)
				.oauth2Login(oauth2Login ->
					oauth2Login
						.tokenEndpoint(tokenEndpoint ->
							tokenEndpoint
								.accessTokenResponseClient(this.mockAccessTokenResponseClient())
						)
						.userInfoEndpoint(userInfoEndpoint ->
							userInfoEndpoint
								.userService(this.mockUserService())
						)
				);
		}
		// @formatter:on

		private OAuth2AccessTokenResponseClient<OAuth2AuthorizationCodeGrantRequest> mockAccessTokenResponseClient() {
			OAuth2AccessTokenResponse accessTokenResponse = OAuth2AccessTokenResponse.withToken("access-token-1234")
				.tokenType(OAuth2AccessToken.TokenType.BEARER)
				.expiresIn(60 * 1000)
				.build();

			OAuth2AccessTokenResponseClient tokenResponseClient = mock(OAuth2AccessTokenResponseClient.class);
			when(tokenResponseClient.getTokenResponse(any())).thenReturn(accessTokenResponse);
			return tokenResponseClient;
		}

		private OAuth2UserService<OAuth2UserRequest, OAuth2User> mockUserService() {
			Map<String, Object> attributes = new HashMap<>();
			attributes.put("id", "joeg");
			attributes.put("first-name", "Joe");
			attributes.put("last-name", "Grandja");
			attributes.put("email", "joeg@springsecurity.io");

			GrantedAuthority authority = new OAuth2UserAuthority(attributes);
			Set<GrantedAuthority> authorities = new HashSet<>();
			authorities.add(authority);

			DefaultOAuth2User user = new DefaultOAuth2User(authorities, attributes, "email");

			OAuth2UserService userService = mock(OAuth2UserService.class);
			when(userService.loadUser(any())).thenReturn(user);
			return userService;
		}
	}

	@SpringBootConfiguration
	@EnableAutoConfiguration
	@ComponentScan(basePackages = "sample.web")
	public static class SpringBootApplicationTestConfig {

		@Bean
		public OAuth2AuthorizedClientService authorizedClientService(ClientRegistrationRepository clientRegistrationRepository) {
			return new InMemoryOAuth2AuthorizedClientService(clientRegistrationRepository);
		}

		@Bean
		public OAuth2AuthorizedClientRepository authorizedClientRepository(OAuth2AuthorizedClientService authorizedClientService) {
			return new AuthenticatedPrincipalOAuth2AuthorizedClientRepository(authorizedClientService);
		}
	}
}
