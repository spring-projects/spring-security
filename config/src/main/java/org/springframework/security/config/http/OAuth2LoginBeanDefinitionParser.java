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

import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanReference;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.http.MediaType;
import org.springframework.security.config.Elements;
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
	private static final String ATT_CLIENT_REGISTRATION_REPOSITORY_REF = "client-registration-repository-ref";
	private static final String ATT_AUTHORIZED_CLIENT_REPOSITORY_REF = "authorized-client-repository-ref";
	private static final String ATT_AUTHORIZED_CLIENT_SERVICE_REF = "authorized-client-service-ref";
	private static final String ATT_AUTHORIZATION_REQUEST_REPOSITORY_REF = "authorization-request-repository-ref";
	private static final String ATT_AUTHORIZATION_REQUEST_RESOLVER_REF = "authorization-request-resolver-ref";
	private static final String ATT_ACCESS_TOKEN_RESPONSE_CLIENT_REF = "access-token-response-client-ref";
	private static final String ATT_USER_AUTHORITIES_MAPPER_REF = "user-authorities-mapper-ref";
	private static final String ATT_USER_SERVICE_REF = "user-service-ref";
	private static final String ATT_OIDC_USER_SERVICE_REF = "oidc-user-service-ref";
	private static final String ATT_LOGIN_PROCESSING_URL = "login-processing-url";
	private static final String ATT_LOGIN_PAGE = "login-page";
	private static final String ATT_AUTHENTICATION_SUCCESS_HANDLER_REF = "authentication-success-handler-ref";
	private static final String ATT_AUTHENTICATION_FAILURE_HANDLER_REF = "authentication-failure-handler-ref";
	private static final String ATT_JWT_DECODER_FACTORY_REF = "jwt-decoder-factory-ref";

	private BeanReference requestCache;

	private BeanDefinition oauth2AuthorizationRequestRedirectFilter;

	private BeanDefinition oauth2LoginAuthenticationEntryPoint;

	private BeanDefinition oauth2LoginAuthenticationProvider;

	private BeanDefinition oauth2LoginOidcAuthenticationProvider;

	OAuth2LoginBeanDefinitionParser(BeanReference requestCache) {
		this.requestCache = requestCache;
	}

	@Override
	public BeanDefinition parse(Element element, ParserContext parserContext) {
		BeanMetadataElement clientRegistrationRepository = getClientRegistrationRepository(element);
		BeanMetadataElement authorizedClientRepository = getAuthorizedClientRepository(element,
				clientRegistrationRepository);
		BeanMetadataElement accessTokenResponseClient = getAccessTokenResponseClient(element);
		BeanMetadataElement oauth2UserService = getOAuth2UserService(element);
		BeanMetadataElement oauth2AuthRequestRepository = getOAuth2AuthorizationRequestRepository(element);

		BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(OAuth2LoginAuthenticationFilter.class)
				.addConstructorArgValue(clientRegistrationRepository).addConstructorArgValue(authorizedClientRepository)
				.addPropertyValue("authorizationRequestRepository", oauth2AuthRequestRepository);

		String loginProcessingUrl = element.getAttribute(ATT_LOGIN_PROCESSING_URL);
		if (!StringUtils.isEmpty(loginProcessingUrl)) {
			builder.addConstructorArgValue(loginProcessingUrl);
		} else {
			builder.addConstructorArgValue(OAuth2LoginAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI);
		}

		BeanDefinitionBuilder oauth2LoginAuthenticationProviderBuilder = BeanDefinitionBuilder
				.rootBeanDefinition(OAuth2LoginAuthenticationProvider.class)
				.addConstructorArgValue(accessTokenResponseClient).addConstructorArgValue(oauth2UserService);

		String oauth2UserAuthMapperRef = element.getAttribute(ATT_USER_AUTHORITIES_MAPPER_REF);
		if (!StringUtils.isEmpty(oauth2UserAuthMapperRef)) {
			oauth2LoginAuthenticationProviderBuilder.addPropertyReference("authoritiesMapper", oauth2UserAuthMapperRef);
		}

		oauth2LoginAuthenticationProvider = oauth2LoginAuthenticationProviderBuilder.getBeanDefinition();

		oauth2LoginOidcAuthenticationProvider = getOAuth2OidcAuthProvider(element, accessTokenResponseClient,
				oauth2UserAuthMapperRef, parserContext);

		BeanDefinitionBuilder oauth2AuthorizationRequestRedirectFilterBuilder = BeanDefinitionBuilder
				.rootBeanDefinition(OAuth2AuthorizationRequestRedirectFilter.class);

		String oauth2AuthorizationRequestResolverRef = element.getAttribute(ATT_AUTHORIZATION_REQUEST_RESOLVER_REF);
		if (!StringUtils.isEmpty(oauth2AuthorizationRequestResolverRef)) {
			oauth2AuthorizationRequestRedirectFilterBuilder
					.addConstructorArgReference(oauth2AuthorizationRequestResolverRef);
		} else {
			oauth2AuthorizationRequestRedirectFilterBuilder.addConstructorArgValue(clientRegistrationRepository);
		}

		oauth2AuthorizationRequestRedirectFilterBuilder
				.addPropertyValue("authorizationRequestRepository", oauth2AuthRequestRepository)
				.addPropertyValue("requestCache", requestCache);
		oauth2AuthorizationRequestRedirectFilter = oauth2AuthorizationRequestRedirectFilterBuilder.getBeanDefinition();

		String authenticationSuccessHandlerRef = element.getAttribute(ATT_AUTHENTICATION_SUCCESS_HANDLER_REF);
		if (!StringUtils.isEmpty(authenticationSuccessHandlerRef)) {
			builder.addPropertyReference("authenticationSuccessHandler", authenticationSuccessHandlerRef);
		}

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

				String authenticationFailureHandlerRef = element.getAttribute(ATT_AUTHENTICATION_FAILURE_HANDLER_REF);
				if (!StringUtils.isEmpty(authenticationFailureHandlerRef)) {
					builder.addPropertyReference("authenticationFailureHandler", authenticationFailureHandlerRef);
				} else {
					BeanDefinitionBuilder failureBuilder = BeanDefinitionBuilder.rootBeanDefinition(
							"org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler");
					failureBuilder.addConstructorArgValue(
							DEFAULT_LOGIN_URI + "?" + DefaultLoginPageGeneratingFilter.ERROR_PARAMETER_NAME);

					builder.addPropertyValue("authenticationFailureHandler", failureBuilder.getBeanDefinition());
				}
			}
		}

		return builder.getBeanDefinition();
	}

	private BeanMetadataElement getOAuth2AuthorizationRequestRepository(Element element) {
		BeanMetadataElement oauth2AuthRequestRepository = null;
		String oauth2AuthRequestRepositoryRef = element.getAttribute(ATT_AUTHORIZATION_REQUEST_REPOSITORY_REF);
		if (!StringUtils.isEmpty(oauth2AuthRequestRepositoryRef)) {
			oauth2AuthRequestRepository = new RuntimeBeanReference(oauth2AuthRequestRepositoryRef);
		} else {
			oauth2AuthRequestRepository = BeanDefinitionBuilder.rootBeanDefinition(
					"org.springframework.security.oauth2.client.web.HttpSessionOAuth2AuthorizationRequestRepository")
					.getBeanDefinition();
		}
		return oauth2AuthRequestRepository;
	}

	private BeanMetadataElement getAuthorizedClientRepository(Element element,
			BeanMetadataElement clientRegistrationRepository) {
		BeanMetadataElement authorizedClientRepository = null;

		String authorizedClientRepositoryRef = element.getAttribute(ATT_AUTHORIZED_CLIENT_REPOSITORY_REF);
		if (!StringUtils.isEmpty(authorizedClientRepositoryRef)) {
			authorizedClientRepository = new RuntimeBeanReference(authorizedClientRepositoryRef);
		} else {
			BeanMetadataElement oauth2AuthorizedClientService = null;
			String authorizedClientServiceRef = element.getAttribute(ATT_AUTHORIZED_CLIENT_SERVICE_REF);
			if (!StringUtils.isEmpty(authorizedClientServiceRef)) {
				oauth2AuthorizedClientService = new RuntimeBeanReference(authorizedClientServiceRef);
			} else {
				oauth2AuthorizedClientService = BeanDefinitionBuilder
						.rootBeanDefinition(
								"org.springframework.security.oauth2.client.InMemoryOAuth2AuthorizedClientService")
						.addConstructorArgValue(clientRegistrationRepository).getBeanDefinition();
			}

			authorizedClientRepository = BeanDefinitionBuilder.rootBeanDefinition(
					"org.springframework.security.oauth2.client.web.AuthenticatedPrincipalOAuth2AuthorizedClientRepository")
					.addConstructorArgValue(oauth2AuthorizedClientService).getBeanDefinition();
		}

		return authorizedClientRepository;
	}

	private BeanMetadataElement getClientRegistrationRepository(Element element) {
		BeanMetadataElement clientRegistrationRepository = null;

		String clientRegistrationRepositoryRef = element.getAttribute(ATT_CLIENT_REGISTRATION_REPOSITORY_REF);
		if (!StringUtils.isEmpty(clientRegistrationRepositoryRef)) {
			clientRegistrationRepository = new RuntimeBeanReference(clientRegistrationRepositoryRef);
		} else {
			clientRegistrationRepository = new RuntimeBeanReference(ClientRegistrationRepository.class);
		}
		return clientRegistrationRepository;
	}

	private BeanDefinition getOAuth2OidcAuthProvider(Element element, BeanMetadataElement accessTokenResponseClient,
			String oauth2UserAuthMapperRef, ParserContext parserContext) {
		BeanDefinition oauth2OidcAuthProvider = null;
		boolean oidcAuthenticationProviderEnabled = ClassUtils
				.isPresent("org.springframework.security.oauth2.jwt.JwtDecoder", this.getClass().getClassLoader());

		if (oidcAuthenticationProviderEnabled) {
			BeanMetadataElement oidcUserService = getOAuth2OidcUserService(element);

			BeanDefinitionBuilder oauth2OidcAuthProviderBuilder = BeanDefinitionBuilder.rootBeanDefinition(
					"org.springframework.security.oauth2.client.oidc.authentication.OidcAuthorizationCodeAuthenticationProvider")
					.addConstructorArgValue(accessTokenResponseClient).addConstructorArgValue(oidcUserService);

			if (!StringUtils.isEmpty(oauth2UserAuthMapperRef)) {
				oauth2OidcAuthProviderBuilder.addPropertyReference("authoritiesMapper", oauth2UserAuthMapperRef);
			}

			String jwtDecoderFactoryRef = element.getAttribute(ATT_JWT_DECODER_FACTORY_REF);
			if (!StringUtils.isEmpty(jwtDecoderFactoryRef)) {
				oauth2OidcAuthProviderBuilder.addPropertyReference("jwtDecoderFactory", jwtDecoderFactoryRef);
			}

			oauth2OidcAuthProvider = oauth2OidcAuthProviderBuilder.getBeanDefinition();
		} else {
			oauth2OidcAuthProvider = BeanDefinitionBuilder.rootBeanDefinition(
					"org.springframework.security.config.annotation.web.configurers.oauth2.client.OAuth2LoginConfigurer.OidcAuthenticationRequestChecker")
					.getBeanDefinition();
		}

		return oauth2OidcAuthProvider;
	}

	private BeanMetadataElement getOAuth2OidcUserService(Element element) {
		BeanMetadataElement oauth2OidcUserService = null;
		String oauth2UserServiceRef = element.getAttribute(ATT_OIDC_USER_SERVICE_REF);
		if (!StringUtils.isEmpty(oauth2UserServiceRef)) {
			oauth2OidcUserService = new RuntimeBeanReference(oauth2UserServiceRef);
		} else {
			oauth2OidcUserService = BeanDefinitionBuilder
					.rootBeanDefinition("org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService")
					.getBeanDefinition();
		}
		return oauth2OidcUserService;
	}

	private BeanMetadataElement getOAuth2UserService(Element element) {
		BeanMetadataElement oauth2UserService = null;
		String oauth2UserServiceRef = element.getAttribute(ATT_USER_SERVICE_REF);
		if (!StringUtils.isEmpty(oauth2UserServiceRef)) {
			oauth2UserService = new RuntimeBeanReference(oauth2UserServiceRef);
		} else {
			oauth2UserService = BeanDefinitionBuilder
					.rootBeanDefinition("org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService")
					.getBeanDefinition();
		}
		return oauth2UserService;
	}

	private BeanMetadataElement getAccessTokenResponseClient(Element element) {
		BeanMetadataElement accessTokenResponseClient = null;

		String accessTokenResponseClientRef = element.getAttribute(ATT_ACCESS_TOKEN_RESPONSE_CLIENT_REF);
		if (!StringUtils.isEmpty(accessTokenResponseClientRef)) {
			accessTokenResponseClient = new RuntimeBeanReference(accessTokenResponseClientRef);
		} else {
			accessTokenResponseClient = BeanDefinitionBuilder.rootBeanDefinition(
					"org.springframework.security.oauth2.client.endpoint.DefaultAuthorizationCodeTokenResponseClient")
					.getBeanDefinition();
		}
		return accessTokenResponseClient;
	}

	BeanDefinition getOAuth2AuthorizationRequestRedirectFilter() {
		return oauth2AuthorizationRequestRedirectFilter;
	}

	BeanDefinition getOAuth2LoginAuthenticationEntryPoint() {
		return oauth2LoginAuthenticationEntryPoint;
	}

	BeanDefinition getOAuth2LoginAuthenticationProvider() {
		return oauth2LoginAuthenticationProvider;
	}

	BeanDefinition getOAuth2LoginOidcAuthenticationProvider() {
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
