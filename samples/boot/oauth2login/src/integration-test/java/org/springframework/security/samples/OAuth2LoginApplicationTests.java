/*
 * Copyright 2012-2017 the original author or authors.
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
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.web.AuthorizationCodeAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.web.AuthorizationCodeRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.AuthorizationGrantTokenExchanger;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.user.OAuth2UserService;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2Parameter;
import org.springframework.security.oauth2.core.endpoint.ResponseType;
import org.springframework.security.oauth2.core.endpoint.TokenResponseAttributes;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.util.*;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Integration tests for the OAuth 2.0 client filters {@link AuthorizationCodeRequestRedirectFilter}
 * and {@link AuthorizationCodeAuthenticationProcessingFilter}.
 * These filters work together to realize the Authorization Code Grant flow.
 *
 * @author Joe Grandja
 */
@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class OAuth2LoginApplicationTests {
	private static final String AUTHORIZATION_BASE_URI = "/oauth2/authorization/code";
	private static final String AUTHORIZE_BASE_URL = "http://localhost:8080/oauth2/authorize/code";

	@Autowired
	private WebClient webClient;

	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;

	private ClientRegistration googleClientRegistration;
	private ClientRegistration githubClientRegistration;
	private ClientRegistration facebookClientRegistration;
	private ClientRegistration oktaClientRegistration;

	@Before
	public void setup() {
		this.webClient.getCookieManager().clearCookies();
		this.googleClientRegistration = this.clientRegistrationRepository.getRegistrationByClientAlias("google");
		this.githubClientRegistration = this.clientRegistrationRepository.getRegistrationByClientAlias("github");
		this.facebookClientRegistration = this.clientRegistrationRepository.getRegistrationByClientAlias("facebook");
		this.oktaClientRegistration = this.clientRegistrationRepository.getRegistrationByClientAlias("okta");
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

		HtmlAnchor clientAnchorElement = this.getClientAnchorElement(page, this.githubClientRegistration);
		assertThat(clientAnchorElement).isNotNull();

		WebResponse response = this.followLinkDisableRedirects(clientAnchorElement);

		assertThat(response.getStatusCode()).isEqualTo(HttpStatus.MOVED_PERMANENTLY.value());

		String authorizeRedirectUri = response.getResponseHeaderValue("Location");
		assertThat(authorizeRedirectUri).isNotNull();

		UriComponents uriComponents = UriComponentsBuilder.fromUri(URI.create(authorizeRedirectUri)).build();

		String requestUri = uriComponents.getScheme() + "://" + uriComponents.getHost() + uriComponents.getPath();
		assertThat(requestUri).isEqualTo(this.githubClientRegistration.getProviderDetails().getAuthorizationUri().toString());

		Map<String, String> params = uriComponents.getQueryParams().toSingleValueMap();

		assertThat(params.get(OAuth2Parameter.RESPONSE_TYPE)).isEqualTo(ResponseType.CODE.getValue());
		assertThat(params.get(OAuth2Parameter.CLIENT_ID)).isEqualTo(this.githubClientRegistration.getClientId());
		String redirectUri = AUTHORIZE_BASE_URL + "/" + this.githubClientRegistration.getClientAlias();
		assertThat(URLDecoder.decode(params.get(OAuth2Parameter.REDIRECT_URI), "UTF-8")).isEqualTo(redirectUri);
		assertThat(URLDecoder.decode(params.get(OAuth2Parameter.SCOPE), "UTF-8"))
				.isEqualTo(this.githubClientRegistration.getScope().stream().collect(Collectors.joining(" ")));
		assertThat(params.get(OAuth2Parameter.STATE)).isNotNull();
	}

	@Test
	public void requestAuthorizeClientWhenInvalidClientThenStatusBadRequest() throws Exception {
		HtmlPage page = this.webClient.getPage("/");

		HtmlAnchor clientAnchorElement = this.getClientAnchorElement(page, this.googleClientRegistration);
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
	public void requestAuthorizationCodeGrantWhenValidAuthorizationResponseThenDisplayIndexPage() throws Exception {
		HtmlPage page = this.webClient.getPage("/");

		HtmlAnchor clientAnchorElement = this.getClientAnchorElement(page, this.githubClientRegistration);
		assertThat(clientAnchorElement).isNotNull();

		WebResponse response = this.followLinkDisableRedirects(clientAnchorElement);

		UriComponents authorizeRequestUriComponents = UriComponentsBuilder.fromUri(
				URI.create(response.getResponseHeaderValue("Location"))).build();

		Map<String, String> params = authorizeRequestUriComponents.getQueryParams().toSingleValueMap();
		String code = "auth-code";
		String state = URLDecoder.decode(params.get(OAuth2Parameter.STATE), "UTF-8");
		String redirectUri = URLDecoder.decode(params.get(OAuth2Parameter.REDIRECT_URI), "UTF-8");

		String authorizationResponseUri =
				UriComponentsBuilder.fromHttpUrl(redirectUri)
						.queryParam(OAuth2Parameter.CODE, code)
						.queryParam(OAuth2Parameter.STATE, state)
						.build().encode().toUriString();

		page = this.webClient.getPage(new URL(authorizationResponseUri));
		this.assertIndexPage(page);
	}

	@Test
	public void requestAuthorizationCodeGrantWhenNoMatchingAuthorizationRequestThenDisplayLoginPageWithError() throws Exception {
		HtmlPage page = this.webClient.getPage("/");
		URL loginPageUrl = page.getBaseURL();
		URL loginErrorPageUrl = new URL(loginPageUrl.toString() + "?error");

		String code = "auth-code";
		String state = "state";
		String redirectUri = AUTHORIZE_BASE_URL + "/" + this.googleClientRegistration.getClientAlias();

		String authorizationResponseUri =
				UriComponentsBuilder.fromHttpUrl(redirectUri)
						.queryParam(OAuth2Parameter.CODE, code)
						.queryParam(OAuth2Parameter.STATE, state)
						.build().encode().toUriString();

		// Clear session cookie will ensure the 'session-saved'
		// Authorization Request (from previous request) is not found
		this.webClient.getCookieManager().clearCookies();

		page = this.webClient.getPage(new URL(authorizationResponseUri));
		assertThat(page.getBaseURL()).isEqualTo(loginErrorPageUrl);

		HtmlElement errorElement = page.getBody().getFirstByXPath("p");
		assertThat(errorElement).isNotNull();
		assertThat(errorElement.asText()).contains("authorization_request_not_found");
	}

	@Test
	public void requestAuthorizationCodeGrantWhenInvalidStateParamThenDisplayLoginPageWithError() throws Exception {
		HtmlPage page = this.webClient.getPage("/");
		URL loginPageUrl = page.getBaseURL();
		URL loginErrorPageUrl = new URL(loginPageUrl.toString() + "?error");

		HtmlAnchor clientAnchorElement = this.getClientAnchorElement(page, this.googleClientRegistration);
		assertThat(clientAnchorElement).isNotNull();
		this.followLinkDisableRedirects(clientAnchorElement);

		String code = "auth-code";
		String state = "invalid-state";
		String redirectUri = AUTHORIZE_BASE_URL + "/" + this.githubClientRegistration.getClientAlias();

		String authorizationResponseUri =
				UriComponentsBuilder.fromHttpUrl(redirectUri)
						.queryParam(OAuth2Parameter.CODE, code)
						.queryParam(OAuth2Parameter.STATE, state)
						.build().encode().toUriString();

		page = this.webClient.getPage(new URL(authorizationResponseUri));
		assertThat(page.getBaseURL()).isEqualTo(loginErrorPageUrl);

		HtmlElement errorElement = page.getBody().getFirstByXPath("p");
		assertThat(errorElement).isNotNull();
		assertThat(errorElement.asText()).contains("invalid_state_parameter");
	}

	@Test
	public void requestAuthorizationCodeGrantWhenInvalidRedirectUriThenDisplayLoginPageWithError() throws Exception {
		HtmlPage page = this.webClient.getPage("/");
		URL loginPageUrl = page.getBaseURL();
		URL loginErrorPageUrl = new URL(loginPageUrl.toString() + "?error");

		HtmlAnchor clientAnchorElement = this.getClientAnchorElement(page, this.googleClientRegistration);
		assertThat(clientAnchorElement).isNotNull();

		WebResponse response = this.followLinkDisableRedirects(clientAnchorElement);

		UriComponents authorizeRequestUriComponents = UriComponentsBuilder.fromUri(
				URI.create(response.getResponseHeaderValue("Location"))).build();

		Map<String, String> params = authorizeRequestUriComponents.getQueryParams().toSingleValueMap();
		String code = "auth-code";
		String state = URLDecoder.decode(params.get(OAuth2Parameter.STATE), "UTF-8");
		String redirectUri = URLDecoder.decode(params.get(OAuth2Parameter.REDIRECT_URI), "UTF-8");
		redirectUri += "-invalid";

		String authorizationResponseUri =
				UriComponentsBuilder.fromHttpUrl(redirectUri)
						.queryParam(OAuth2Parameter.CODE, code)
						.queryParam(OAuth2Parameter.STATE, state)
						.build().encode().toUriString();

		page = this.webClient.getPage(new URL(authorizationResponseUri));
		assertThat(page.getBaseURL()).isEqualTo(loginErrorPageUrl);

		HtmlElement errorElement = page.getBody().getFirstByXPath("p");
		assertThat(errorElement).isNotNull();
		assertThat(errorElement.asText()).contains("invalid_redirect_uri_parameter");
	}

	@Test
	public void requestAuthorizationCodeGrantWhenStandardErrorCodeResponseThenDisplayLoginPageWithError() throws Exception {
		HtmlPage page = this.webClient.getPage("/");
		URL loginPageUrl = page.getBaseURL();
		URL loginErrorPageUrl = new URL(loginPageUrl.toString() + "?error");

		String error = OAuth2Error.INVALID_CLIENT_ERROR_CODE;
		String state = "state";
		String redirectUri = AUTHORIZE_BASE_URL + "/" + this.githubClientRegistration.getClientAlias();

		String authorizationResponseUri =
				UriComponentsBuilder.fromHttpUrl(redirectUri)
						.queryParam(OAuth2Parameter.ERROR, error)
						.queryParam(OAuth2Parameter.STATE, state)
						.build().encode().toUriString();

		page = this.webClient.getPage(new URL(authorizationResponseUri));
		assertThat(page.getBaseURL()).isEqualTo(loginErrorPageUrl);

		HtmlElement errorElement = page.getBody().getFirstByXPath("p");
		assertThat(errorElement).isNotNull();
		assertThat(errorElement.asText()).contains(error);
	}

	private void assertLoginPage(HtmlPage page) throws Exception {
		assertThat(page.getTitleText()).isEqualTo("Login Page");

		int expectedClients = 4;

		List<HtmlAnchor> clientAnchorElements = page.getAnchors();
		assertThat(clientAnchorElements.size()).isEqualTo(expectedClients);

		String baseAuthorizeUri = AUTHORIZATION_BASE_URI + "/";
		String googleClientAuthorizeUri = baseAuthorizeUri + this.googleClientRegistration.getClientAlias();
		String githubClientAuthorizeUri = baseAuthorizeUri + this.githubClientRegistration.getClientAlias();
		String facebookClientAuthorizeUri = baseAuthorizeUri + this.facebookClientRegistration.getClientAlias();
		String oktaClientAuthorizeUri = baseAuthorizeUri + this.oktaClientRegistration.getClientAlias();

		for (int i=0; i<expectedClients; i++) {
			assertThat(clientAnchorElements.get(i).getAttribute("href")).isIn(
				googleClientAuthorizeUri, githubClientAuthorizeUri,
				facebookClientAuthorizeUri, oktaClientAuthorizeUri);
			assertThat(clientAnchorElements.get(i).asText()).isIn(
				this.googleClientRegistration.getClientName(),
				this.githubClientRegistration.getClientName(),
				this.facebookClientRegistration.getClientName(),
				this.oktaClientRegistration.getClientName());
		}
	}

	private void assertIndexPage(HtmlPage page) throws Exception {
		assertThat(page.getTitleText()).isEqualTo("Spring Security - OAuth 2.0 Login");

		DomNodeList<HtmlElement> divElements = page.getBody().getElementsByTagName("div");
		assertThat(divElements.get(1).asText()).contains("User: joeg@springsecurity.io");
		assertThat(divElements.get(4).asText()).contains("You are successfully logged in joeg@springsecurity.io");
	}

	private HtmlAnchor getClientAnchorElement(HtmlPage page, ClientRegistration clientRegistration) {
		Optional<HtmlAnchor> clientAnchorElement = page.getAnchors().stream()
				.filter(e -> e.asText().equals(clientRegistration.getClientName())).findFirst();

		return (clientAnchorElement.isPresent() ? clientAnchorElement.get() : null);
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
				.authorizeRequests()
					.anyRequest().authenticated()
					.and()
				.oauth2Login()
					.tokenEndpoint()
						.authorizationCodeTokenExchanger(this.mockAuthorizationCodeTokenExchanger())
						.and()
					.userInfoEndpoint()
						.userInfoService(this.mockUserInfoService());
		}
		// @formatter:on

		private AuthorizationGrantTokenExchanger<AuthorizationCodeAuthenticationToken> mockAuthorizationCodeTokenExchanger() {
			TokenResponseAttributes tokenResponse = TokenResponseAttributes.withToken("access-token-1234")
				.tokenType(AccessToken.TokenType.BEARER)
				.expiresIn(60 * 1000)
				.scopes(Collections.singleton("openid"))
				.build();

			AuthorizationGrantTokenExchanger mock = mock(AuthorizationGrantTokenExchanger.class);
			when(mock.exchange(any())).thenReturn(tokenResponse);
			return mock;
		}

		private OAuth2UserService mockUserInfoService() {
			Map<String, Object> attributes = new HashMap<>();
			attributes.put("id", "joeg");
			attributes.put("first-name", "Joe");
			attributes.put("last-name", "Grandja");
			attributes.put("email", "joeg@springsecurity.io");

			GrantedAuthority authority = new OAuth2UserAuthority(attributes);
			Set<GrantedAuthority> authorities = new HashSet<>();
			authorities.add(authority);

			DefaultOAuth2User user = new DefaultOAuth2User(authorities, attributes, "email");

			OAuth2UserService mock = mock(OAuth2UserService.class);
			when(mock.loadUser(any())).thenReturn(user);
			return mock;
		}
	}

	@SpringBootConfiguration
	@EnableAutoConfiguration
	@ComponentScan(basePackages = "sample.web")
	public static class SpringBootApplicationTestConfig {
	}
}
