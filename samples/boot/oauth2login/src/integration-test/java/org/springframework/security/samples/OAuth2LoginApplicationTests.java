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
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.SpringBootConfiguration;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeGrantAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.AuthorizationCodeGrantProcessingFilter;
import org.springframework.security.oauth2.client.authentication.AuthorizationGrantTokenExchanger;
import org.springframework.security.oauth2.client.authorization.AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationProperties;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.userdetails.UserInfoUserDetailsService;
import org.springframework.security.oauth2.core.AccessToken;
import org.springframework.security.oauth2.core.OAuth2Attributes;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.ResponseType;
import org.springframework.security.oauth2.core.protocol.TokenResponseAttributes;
import org.springframework.security.oauth2.core.userdetails.OAuth2User;
import org.springframework.security.oauth2.core.userdetails.OAuth2UserAttribute;
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
import static org.springframework.security.oauth2.client.config.annotation.web.configurers.OAuth2LoginSecurityConfigurer.oauth2Login;

/**
 * Integration tests for the OAuth2 client filters {@link AuthorizationRequestRedirectFilter}
 * and {@link AuthorizationCodeGrantProcessingFilter}.
 *
 * @author Joe Grandja
 */
@RunWith(SpringRunner.class)
@SpringBootTest
@AutoConfigureMockMvc
public class OAuth2LoginApplicationTests {

	@Autowired
	private WebClient webClient;

	@Autowired
	@Qualifier("googleClientRegistration")
	private ClientRegistration googleClientRegistration;

	@Autowired
	@Qualifier("githubClientRegistration")
	private ClientRegistration githubClientRegistration;


	@Before
	public void setup() {
		this.webClient.getCookieManager().clearCookies();
	}

	@Test
	public void requestHomePageWhenNotAuthenticatedThenDisplayClientsPage() throws Exception {
		HtmlPage page = this.webClient.getPage("/");
		this.assertClientsPage(page);
	}

	@Test
	public void requestOtherPageWhenNotAuthenticatedThenDisplayClientsPage() throws Exception {
		HtmlPage page = this.webClient.getPage("/other-page");
		this.assertClientsPage(page);
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

		assertThat(params.get(OAuth2Attributes.RESPONSE_TYPE)).isEqualTo(ResponseType.CODE.value());
		assertThat(params.get(OAuth2Attributes.CLIENT_ID)).isEqualTo(this.githubClientRegistration.getClientId());
		assertThat(URLDecoder.decode(params.get(OAuth2Attributes.REDIRECT_URI), "UTF-8"))
				.isEqualTo(this.githubClientRegistration.getRedirectUri().toString());
		assertThat(URLDecoder.decode(params.get(OAuth2Attributes.SCOPE), "UTF-8"))
				.isEqualTo(this.githubClientRegistration.getScopes().stream().collect(Collectors.joining(" ")));
		assertThat(params.get(OAuth2Attributes.STATE)).isNotNull();
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
	public void requestAuthorizationCodeGrantWhenValidAuthorizationResponseThenDisplayUserInfoPage() throws Exception {
		HtmlPage page = this.webClient.getPage("/");

		HtmlAnchor clientAnchorElement = this.getClientAnchorElement(page, this.githubClientRegistration);
		assertThat(clientAnchorElement).isNotNull();

		WebResponse response = this.followLinkDisableRedirects(clientAnchorElement);

		UriComponents authorizeRequestUriComponents = UriComponentsBuilder.fromUri(
				URI.create(response.getResponseHeaderValue("Location"))).build();

		Map<String, String> params = authorizeRequestUriComponents.getQueryParams().toSingleValueMap();
		String code = "auth-code";
		String state = URLDecoder.decode(params.get(OAuth2Attributes.STATE), "UTF-8");
		String redirectUri = URLDecoder.decode(params.get(OAuth2Attributes.REDIRECT_URI), "UTF-8");

		String authorizationResponseUri =
				UriComponentsBuilder.fromHttpUrl(redirectUri)
						.queryParam(OAuth2Attributes.CODE, code)
						.queryParam(OAuth2Attributes.STATE, state)
						.build().encode().toUriString();

		page = this.webClient.getPage(new URL(authorizationResponseUri));
		this.assertUserInfoPage(page);
	}

	@Test
	public void requestAuthorizationCodeGrantWhenNoMatchingAuthorizationRequestThenDisplayClientsPageWithError() throws Exception {
		HtmlPage page = this.webClient.getPage("/");
		URL clientsPageUrl = page.getBaseURL();
		URL clientsErrorPageUrl = new URL(clientsPageUrl.toString() + "?error");

		String code = "auth-code";
		String state = "state";
		String redirectUri = this.googleClientRegistration.getRedirectUri().toString();

		String authorizationResponseUri =
				UriComponentsBuilder.fromHttpUrl(redirectUri)
						.queryParam(OAuth2Attributes.CODE, code)
						.queryParam(OAuth2Attributes.STATE, state)
						.build().encode().toUriString();

		// Clear session cookie will ensure the 'session-saved'
		// Authorization Request (from previous request) is not found
		this.webClient.getCookieManager().clearCookies();

		page = this.webClient.getPage(new URL(authorizationResponseUri));
		assertThat(page.getBaseURL()).isEqualTo(clientsErrorPageUrl);

		HtmlElement errorElement = page.getBody().getFirstByXPath("p");
		assertThat(errorElement).isNotNull();
		assertThat(errorElement.asText()).contains(OAuth2Error.ErrorCode.AUTHORIZATION_REQUEST_NOT_FOUND.toString());
	}

	@Test
	public void requestAuthorizationCodeGrantWhenInvalidStateParamThenDisplayClientsPageWithError() throws Exception {
		HtmlPage page = this.webClient.getPage("/");
		URL clientsPageUrl = page.getBaseURL();
		URL clientsErrorPageUrl = new URL(clientsPageUrl.toString() + "?error");

		HtmlAnchor clientAnchorElement = this.getClientAnchorElement(page, this.googleClientRegistration);
		assertThat(clientAnchorElement).isNotNull();
		this.followLinkDisableRedirects(clientAnchorElement);

		String code = "auth-code";
		String state = "invalid-state";
		String redirectUri = this.githubClientRegistration.getRedirectUri().toString();

		String authorizationResponseUri =
				UriComponentsBuilder.fromHttpUrl(redirectUri)
						.queryParam(OAuth2Attributes.CODE, code)
						.queryParam(OAuth2Attributes.STATE, state)
						.build().encode().toUriString();

		page = this.webClient.getPage(new URL(authorizationResponseUri));
		assertThat(page.getBaseURL()).isEqualTo(clientsErrorPageUrl);

		HtmlElement errorElement = page.getBody().getFirstByXPath("p");
		assertThat(errorElement).isNotNull();
		assertThat(errorElement.asText()).contains(OAuth2Error.ErrorCode.INVALID_STATE_PARAMETER.toString());
	}

	@Test
	public void requestAuthorizationCodeGrantWhenInvalidRedirectUriThenDisplayClientsPageWithError() throws Exception {
		HtmlPage page = this.webClient.getPage("/");
		URL clientsPageUrl = page.getBaseURL();
		URL clientsErrorPageUrl = new URL(clientsPageUrl.toString() + "?error");

		HtmlAnchor clientAnchorElement = this.getClientAnchorElement(page, this.googleClientRegistration);
		assertThat(clientAnchorElement).isNotNull();

		WebResponse response = this.followLinkDisableRedirects(clientAnchorElement);

		UriComponents authorizeRequestUriComponents = UriComponentsBuilder.fromUri(
				URI.create(response.getResponseHeaderValue("Location"))).build();

		Map<String, String> params = authorizeRequestUriComponents.getQueryParams().toSingleValueMap();
		String code = "auth-code";
		String state = URLDecoder.decode(params.get(OAuth2Attributes.STATE), "UTF-8");
		String redirectUri = URLDecoder.decode(params.get(OAuth2Attributes.REDIRECT_URI), "UTF-8");
		redirectUri += "-invalid";

		String authorizationResponseUri =
				UriComponentsBuilder.fromHttpUrl(redirectUri)
						.queryParam(OAuth2Attributes.CODE, code)
						.queryParam(OAuth2Attributes.STATE, state)
						.build().encode().toUriString();

		page = this.webClient.getPage(new URL(authorizationResponseUri));
		assertThat(page.getBaseURL()).isEqualTo(clientsErrorPageUrl);

		HtmlElement errorElement = page.getBody().getFirstByXPath("p");
		assertThat(errorElement).isNotNull();
		assertThat(errorElement.asText()).contains(OAuth2Error.ErrorCode.INVALID_REDIRECT_URI_PARAMETER.toString());
	}

	@Test
	public void requestAuthorizationCodeGrantWhenValidAuthorizationErrorResponseThenDisplayClientsPageWithError() throws Exception {
		HtmlPage page = this.webClient.getPage("/");
		URL clientsPageUrl = page.getBaseURL();
		URL clientsErrorPageUrl = new URL(clientsPageUrl.toString() + "?error");

		String error = OAuth2Error.ErrorCode.UNAUTHORIZED_CLIENT.toString();
		String state = "state";
		String redirectUri = this.githubClientRegistration.getRedirectUri().toString();

		String authorizationResponseUri =
				UriComponentsBuilder.fromHttpUrl(redirectUri)
						.queryParam(OAuth2Attributes.ERROR, error)
						.queryParam(OAuth2Attributes.STATE, state)
						.build().encode().toUriString();

		page = this.webClient.getPage(new URL(authorizationResponseUri));
		assertThat(page.getBaseURL()).isEqualTo(clientsErrorPageUrl);

		HtmlElement errorElement = page.getBody().getFirstByXPath("p");
		assertThat(errorElement).isNotNull();
		assertThat(errorElement.asText()).contains(error);
	}

	@Test
	public void requestAuthorizationCodeGrantWhenInvalidErrorCodeThenDisplayClientsPageWithError() throws Exception {
		HtmlPage page = this.webClient.getPage("/");
		URL clientsPageUrl = page.getBaseURL();
		URL clientsErrorPageUrl = new URL(clientsPageUrl.toString() + "?error");

		String error = "invalid-error-code";
		String state = "state";
		String redirectUri = this.googleClientRegistration.getRedirectUri().toString();

		String authorizationResponseUri =
				UriComponentsBuilder.fromHttpUrl(redirectUri)
						.queryParam(OAuth2Attributes.ERROR, error)
						.queryParam(OAuth2Attributes.STATE, state)
						.build().encode().toUriString();

		page = this.webClient.getPage(new URL(authorizationResponseUri));
		assertThat(page.getBaseURL()).isEqualTo(clientsErrorPageUrl);

		HtmlElement errorElement = page.getBody().getFirstByXPath("p");
		assertThat(errorElement).isNotNull();
		assertThat(errorElement.asText()).contains(OAuth2Error.ErrorCode.UNKNOWN_ERROR_CODE.toString());
	}

	private void assertClientsPage(HtmlPage page) throws Exception {
		assertThat(page.getTitleText()).isEqualTo("OAuth2 Client Login Page");

		assertThat(page.getElementsByTagName("li").size()).isEqualTo(2);

		List<HtmlAnchor> clientAnchorElements = page.getAnchors();
		assertThat(clientAnchorElements.size()).isEqualTo(2);

		String baseAuthorizeUri = AuthorizationRequestRedirectFilter.DEFAULT_FILTER_PROCESSING_URI + "/";
		String googleClientAuthorizeUri = baseAuthorizeUri + this.googleClientRegistration.getClientAlias();
		String githubClientAuthorizeUri = baseAuthorizeUri + this.githubClientRegistration.getClientAlias();

		assertThat(clientAnchorElements.get(0).getAttribute("href")).isIn(googleClientAuthorizeUri, githubClientAuthorizeUri);
		assertThat(clientAnchorElements.get(0).asText()).isIn(
				this.googleClientRegistration.getClientName(), this.githubClientRegistration.getClientName());

		assertThat(clientAnchorElements.get(1).getAttribute("href")).isIn(googleClientAuthorizeUri, githubClientAuthorizeUri);
		assertThat(clientAnchorElements.get(1).asText()).isIn(
				this.googleClientRegistration.getClientName(), this.githubClientRegistration.getClientName());
	}

	private void assertUserInfoPage(HtmlPage page) throws Exception {
		assertThat(page.getTitleText()).isEqualTo("Spring Security - OAuth2 User Info");

		DomNodeList<HtmlElement> divElements = page.getBody().getElementsByTagName("div");
		assertThat(divElements.get(1).asText()).contains("User: joeg@springsecurity.io");
		assertThat(divElements.get(4).asText()).contains("Identifier: joeg");
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

	@Configuration
	@EnableWebSecurity
	public static class SecurityTestConfig extends WebSecurityConfigurerAdapter {

		// @formatter:off
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.authorizeRequests()
						.anyRequest().authenticated()
						.and()
					.apply(oauth2Login()
							.authorizationCodeGrantTokenExchanger(this.mockAuthorizationCodeGrantTokenExchanger())
							.userInfoEndpoint()
								.userInfoService(this.mockUserInfoEndpointService()));
		}
		// @formatter:on

		@ConfigurationProperties(prefix = "security.oauth2.client.google")
		@Bean
		public ClientRegistrationProperties googleClientRegistrationProperties() {
			return new ClientRegistrationProperties();
		}

		@Bean
		public ClientRegistration googleClientRegistration() {
			return new ClientRegistration.Builder(this.googleClientRegistrationProperties()).build();
		}

		@ConfigurationProperties(prefix = "security.oauth2.client.github")
		@Bean
		public ClientRegistrationProperties githubClientRegistrationProperties() {
			return new ClientRegistrationProperties();
		}

		@Bean
		public ClientRegistration githubClientRegistration() {
			return new ClientRegistration.Builder(this.githubClientRegistrationProperties()).build();
		}

		private AuthorizationGrantTokenExchanger<AuthorizationCodeGrantAuthenticationToken> mockAuthorizationCodeGrantTokenExchanger() {
			TokenResponseAttributes tokenResponse = new TokenResponseAttributes(
					"access-token-1234", AccessToken.TokenType.BEARER, 60 * 1000, Collections.singleton("openid"));

			AuthorizationGrantTokenExchanger mock = mock(AuthorizationGrantTokenExchanger.class);
			when(mock.exchange(any())).thenReturn(tokenResponse);
			return mock;
		}

		private UserInfoUserDetailsService mockUserInfoEndpointService() {
			OAuth2UserAttribute identifierAttribute = new OAuth2UserAttribute("id", "joeg");
			OAuth2UserAttribute firstNameAttribute = new OAuth2UserAttribute("first-name", "Joe");
			OAuth2UserAttribute lastNameAttribute = new OAuth2UserAttribute("last-name", "Grandja");
			OAuth2UserAttribute emailAttribute = new OAuth2UserAttribute("email", "joeg@springsecurity.io");
			OAuth2User userDetails = new OAuth2User(identifierAttribute, Arrays.asList(firstNameAttribute, lastNameAttribute, emailAttribute));
			userDetails.setUserNameAttributeName("email");

			UserInfoUserDetailsService mock = mock(UserInfoUserDetailsService.class);
			when(mock.loadUserDetails(any())).thenReturn(userDetails);
			return mock;
		}
	}

	@SpringBootConfiguration
	@EnableAutoConfiguration
	@ComponentScan(basePackages = "org.springframework.security.samples.web")
	public static class SpringBootApplicationTestConfig {

		@Bean
		public ClientRegistrationRepository clientRegistrationRepository(List<ClientRegistration> clientRegistrations) {
			return new InMemoryClientRegistrationRepository(clientRegistrations);
		}
	}
}
