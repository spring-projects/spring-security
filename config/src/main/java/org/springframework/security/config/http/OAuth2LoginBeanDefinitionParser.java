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

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.http.MediaType;
import org.springframework.security.config.Elements;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationProvider;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestRedirectFilter;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestHeaderRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;
import org.springframework.web.accept.ContentNegotiationStrategy;
import org.springframework.web.accept.HeaderContentNegotiationStrategy;
import org.w3c.dom.Element;

/**
 * @author Ruby Hartono
 */
final class OAuth2LoginBeanDefinitionParser implements BeanDefinitionParser {

	private static final String DEFAULT_AUTHORIZATION_REQUEST_BASE_URI = "/oauth2/authorization";
	private static final String DEFAULT_LOGIN_URI = DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL;

	private static final String ELT_CLIENT_REGISTRATION = "client-registration";
	private static final String ATT_REGISTRATION_ID = "registration-id";
	private static final String ATT_TOKENENDPOINT_ACCESS_TOKEN_RESPONSE_CLIENT_REF = "tokenendpoint-access-token-response-client-ref";
	private static final String ATT_USERINFO_USER_SERVICE_REF = "userinfo-user-service-ref";
	private static final String ATT_USERINFO_OIDC_USER_SERVICE_REF = "userinfo-oidc-user-service-ref";
	private static final String ATT_USERINFO_USER_AUTH_MAPPER_REF = "userinfo-user-authorities-mapper-ref";
	private static final String ATT_LOGIN_PROCESSING_URL = "login-processing-url";
	private static final String ATT_AUTHORIZATIONENDPOINT_AUTH_REQ_RESOLVER_REF = "authorizationendpoint-authorization-request-resolver-ref";
	private static final String ATT_LOGIN_PAGE = "login-page";

	private BeanDefinition oauth2AuthorizationRequestRedirectFilter;

	private BeanDefinition oauth2LoginAuthenticationEntryPoint;

	private BeanDefinition oauth2LoginAuthenticationProvider;

	private BeanDefinition oauth2LoginOidcAuthenticationProvider;

	@Override
	public BeanDefinition parse(Element element, ParserContext parserContext) {
		BeanMetadataElement accessTokenResponseClient = retrieveAccessTokenResponseClient(element);
		BeanMetadataElement oauth2UserService = retrieveOAuth2UserService(element);
		BeanMetadataElement oauth2AuthRequestRepository = BeanDefinitionBuilder.rootBeanDefinition(
				"org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository")
				.getBeanDefinition();

		BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(OAuth2LoginAuthenticationFilter.class)
				.addConstructorArgValue(new RuntimeBeanReference(ClientRegistrationRepository.class))
				.addConstructorArgValue(new RuntimeBeanReference(OAuth2AuthorizedClientService.class))
				.addPropertyValue("authorizationRequestRepository", oauth2AuthRequestRepository);

		String loginProcessingUrl = element.getAttribute(ATT_LOGIN_PROCESSING_URL);
		if (!StringUtils.isEmpty(loginProcessingUrl)) {
			builder.addConstructorArgValue(loginProcessingUrl);
		}

		BeanDefinitionBuilder oauth2LoginAuthenticationProviderBuilder = BeanDefinitionBuilder
				.rootBeanDefinition(OAuth2LoginAuthenticationProvider.class)
				.addConstructorArgValue(accessTokenResponseClient).addConstructorArgValue(oauth2UserService);

		String oauth2UserAuthMapperRef = element.getAttribute(ATT_USERINFO_USER_AUTH_MAPPER_REF);
		if (!StringUtils.isEmpty(oauth2UserAuthMapperRef)) {
			oauth2LoginAuthenticationProviderBuilder.addPropertyReference("authoritiesMapper", oauth2UserAuthMapperRef);
		}

		oauth2LoginAuthenticationProvider = oauth2LoginAuthenticationProviderBuilder.getBeanDefinition();

		oauth2LoginOidcAuthenticationProvider = retrieveOAuth2OidcAuthProvider(element, accessTokenResponseClient,
				oauth2UserAuthMapperRef, parserContext);

		BeanDefinitionBuilder oauth2AuthorizationRequestRedirectFilterBuilder = BeanDefinitionBuilder
				.rootBeanDefinition(OAuth2AuthorizationRequestRedirectFilter.class);

		String oauth2AuthorizationRequestResolverRef = element
				.getAttribute(ATT_AUTHORIZATIONENDPOINT_AUTH_REQ_RESOLVER_REF);
		if (!StringUtils.isEmpty(oauth2AuthorizationRequestResolverRef)) {
			oauth2AuthorizationRequestRedirectFilterBuilder
					.addConstructorArgReference(oauth2AuthorizationRequestResolverRef);
		} else {
			oauth2AuthorizationRequestRedirectFilterBuilder
					.addConstructorArgValue(new RuntimeBeanReference(ClientRegistrationRepository.class));
		}

		oauth2AuthorizationRequestRedirectFilterBuilder.addPropertyValue("authorizationRequestRepository",
				oauth2AuthRequestRepository);
		oauth2AuthorizationRequestRedirectFilter = oauth2AuthorizationRequestRedirectFilterBuilder.getBeanDefinition();

		String loginPage = element.getAttribute(ATT_LOGIN_PAGE);
		if (!StringUtils.isEmpty(loginPage)) {
			oauth2LoginAuthenticationEntryPoint = BeanDefinitionBuilder
					.rootBeanDefinition(LoginUrlAuthenticationEntryPoint.class).addConstructorArgValue(loginPage)
					.getBeanDefinition();
		} else {
			Map<RequestMatcher, AuthenticationEntryPoint> entryPoint = getLoginEntryPoint(element, parserContext);

			if (entryPoint != null) {
				oauth2LoginAuthenticationEntryPoint = BeanDefinitionBuilder
						.rootBeanDefinition(DelegatingAuthenticationEntryPoint.class).addConstructorArgValue(entryPoint)
						.addPropertyValue("defaultEntryPoint", new LoginUrlAuthenticationEntryPoint(DEFAULT_LOGIN_URI))
						.getBeanDefinition();

				BeanDefinitionBuilder failureBuilder = BeanDefinitionBuilder.rootBeanDefinition(
						"org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler");
				failureBuilder.addConstructorArgValue(
						DEFAULT_LOGIN_URI + "?" + DefaultLoginPageGeneratingFilter.ERROR_PARAMETER_NAME);

				builder.addPropertyValue("authenticationFailureHandler", failureBuilder.getBeanDefinition());
			}
		}

		return builder.getBeanDefinition();
	}

	private BeanDefinition retrieveOAuth2OidcAuthProvider(Element element,
			BeanMetadataElement accessTokenResponseClient, String oauth2UserAuthMapperRef,
			ParserContext parserContext) {
		BeanDefinition oauth2OidcAuthProvider = null;
		boolean oidcAuthenticationProviderEnabled = ClassUtils
				.isPresent("org.springframework.security.oauth2.jwt.JwtDecoder", this.getClass().getClassLoader());

		if (oidcAuthenticationProviderEnabled) {
			BeanMetadataElement oidcUserService = retrieveOAuth2OidcUserService(element);

			BeanDefinitionBuilder oauth2OidcAuthProviderBuilder = BeanDefinitionBuilder.rootBeanDefinition(
					"org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeAuthenticationProvider")
					.addConstructorArgValue(accessTokenResponseClient).addConstructorArgValue(oidcUserService);

			if (!StringUtils.isEmpty(oauth2UserAuthMapperRef)) {
				oauth2OidcAuthProviderBuilder.addPropertyReference("authoritiesMapper", oauth2UserAuthMapperRef);
			}

			oauth2OidcAuthProvider = oauth2OidcAuthProviderBuilder.getBeanDefinition();
		} else {
			oauth2OidcAuthProvider = BeanDefinitionBuilder.rootBeanDefinition(
					"org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer.OidcAuthenticationRequestChecker")
					.getBeanDefinition();
		}

		return oauth2OidcAuthProvider;
	}

	private BeanMetadataElement retrieveOAuth2OidcUserService(Element element) {
		BeanMetadataElement oauth2OidcUserService = null;
		String oauth2UserServiceRef = element.getAttribute(ATT_USERINFO_OIDC_USER_SERVICE_REF);
		if (!StringUtils.isEmpty(oauth2UserServiceRef)) {
			oauth2OidcUserService = new RuntimeBeanReference(oauth2UserServiceRef);
		} else {
			oauth2OidcUserService = BeanDefinitionBuilder
					.rootBeanDefinition("org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService")
					.getBeanDefinition();
		}
		return oauth2OidcUserService;
	}

	private BeanMetadataElement retrieveOAuth2UserService(Element element) {
		BeanMetadataElement oauth2UserService = null;
		String oauth2UserServiceRef = element.getAttribute(ATT_USERINFO_USER_SERVICE_REF);
		if (!StringUtils.isEmpty(oauth2UserServiceRef)) {
			oauth2UserService = new RuntimeBeanReference(oauth2UserServiceRef);
		} else {
			oauth2UserService = BeanDefinitionBuilder
					.rootBeanDefinition("org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService")
					.getBeanDefinition();
		}
		return oauth2UserService;
	}

	private BeanMetadataElement retrieveAccessTokenResponseClient(Element element) {
		BeanMetadataElement accessTokenResponseClient = null;

		String accessTokenResponseClientRef = element.getAttribute(ATT_TOKENENDPOINT_ACCESS_TOKEN_RESPONSE_CLIENT_REF);
		if (!StringUtils.isEmpty(accessTokenResponseClientRef)) {
			accessTokenResponseClient = new RuntimeBeanReference(accessTokenResponseClientRef);
		} else {
			accessTokenResponseClient = BeanDefinitionBuilder.rootBeanDefinition(
					"org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient")
					.getBeanDefinition();
		}
		return accessTokenResponseClient;
	}

	public BeanDefinition getOAuth2AuthorizationRequestRedirectFilter() {
		return oauth2AuthorizationRequestRedirectFilter;
	}

	public BeanDefinition getOAuth2LoginAuthenticationEntryPoint() {
		return oauth2LoginAuthenticationEntryPoint;
	}

	public BeanDefinition getOAuth2LoginAuthenticationProvider() {
		return oauth2LoginAuthenticationProvider;
	}

	public BeanDefinition getOAuth2LoginOidcAuthenticationProvider() {
		return oauth2LoginOidcAuthenticationProvider;
	}

	private Map<RequestMatcher, AuthenticationEntryPoint> getLoginEntryPoint(Element element,
			ParserContext parserContext) {
		Map<RequestMatcher, AuthenticationEntryPoint> entryPoints = null;
		Element clientRegsElt = DomUtils.getChildElementByTagName(element.getOwnerDocument().getDocumentElement(),
				Elements.CLIENT_REGISTRATIONS);

		if (clientRegsElt != null) {
			List<Element> clientRegList = DomUtils.getChildElementsByTagName(clientRegsElt, ELT_CLIENT_REGISTRATION);

			if (clientRegList.size() == 1) {
				RequestMatcher loginPageMatcher = new AntPathRequestMatcher(DEFAULT_LOGIN_URI);
				RequestMatcher faviconMatcher = new AntPathRequestMatcher("/favicon.ico");
				RequestMatcher defaultEntryPointMatcher = this.getAuthenticationEntryPointMatcher();
				RequestMatcher defaultLoginPageMatcher = new AndRequestMatcher(
						new OrRequestMatcher(loginPageMatcher, faviconMatcher), defaultEntryPointMatcher);

				RequestMatcher notXRequestedWith = new NegatedRequestMatcher(
						new RequestHeaderRequestMatcher("X-Requested-With", "XMLHttpRequest"));

				Element clientRegElt = clientRegList.get(0);
				entryPoints = new LinkedHashMap<>();
				entryPoints.put(
						new AndRequestMatcher(notXRequestedWith, new NegatedRequestMatcher(defaultLoginPageMatcher)),
						new LoginUrlAuthenticationEntryPoint(DEFAULT_AUTHORIZATION_REQUEST_BASE_URI + "/"
								+ clientRegElt.getAttribute(ATT_REGISTRATION_ID)));

			}
		}

		return entryPoints;
	}

	private RequestMatcher getAuthenticationEntryPointMatcher() {
		ContentNegotiationStrategy contentNegotiationStrategy = new HeaderContentNegotiationStrategy();

		MediaTypeRequestMatcher mediaMatcher = new MediaTypeRequestMatcher(contentNegotiationStrategy,
				MediaType.APPLICATION_XHTML_XML, new MediaType("image", "*"), MediaType.TEXT_HTML,
				MediaType.TEXT_PLAIN);
		mediaMatcher.setIgnoredMediaTypes(Collections.singleton(MediaType.ALL));

		RequestMatcher notXRequestedWith = new NegatedRequestMatcher(
				new RequestHeaderRequestMatcher("X-Requested-With", "XMLHttpRequest"));

		return new AndRequestMatcher(Arrays.asList(notXRequestedWith, mediaMatcher));
	}
}
