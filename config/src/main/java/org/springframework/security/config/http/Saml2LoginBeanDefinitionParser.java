/*
 * Copyright 2002-2022 the original author or authors.
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

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.w3c.dom.Element;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.BeanReference;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.ResolvableType;
import org.springframework.security.config.Elements;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.Saml2WebSsoAuthenticationRequestFilter;
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;

/**
 * SAML 2.0 Login {@link BeanDefinitionParser}
 *
 * @author Marcus da Coregio
 * @since 5.7
 */
final class Saml2LoginBeanDefinitionParser implements BeanDefinitionParser {

	private static final String DEFAULT_LOGIN_URI = DefaultLoginPageGeneratingFilter.DEFAULT_LOGIN_PAGE_URL;

	private static final String DEFAULT_AUTHENTICATION_REQUEST_PROCESSING_URL = "/saml2/authenticate/{registrationId}";

	private static final String ATT_LOGIN_PROCESSING_URL = "login-processing-url";

	private static final String ATT_LOGIN_PAGE = "login-page";

	private static final String ELT_RELYING_PARTY_REGISTRATION = "relying-party-registration";

	private static final String ELT_REGISTRATION_ID = "registration-id";

	private static final String ATT_AUTHENTICATION_FAILURE_HANDLER_REF = "authentication-failure-handler-ref";

	private static final String ATT_AUTHENTICATION_SUCCESS_HANDLER_REF = "authentication-success-handler-ref";

	private static final String ATT_AUTHENTICATION_MANAGER_REF = "authentication-manager-ref";

	private final List<BeanDefinition> csrfIgnoreRequestMatchers;

	private final BeanReference portMapper;

	private final BeanReference portResolver;

	private final BeanReference requestCache;

	private final boolean allowSessionCreation;

	private final BeanReference authenticationManager;

	private final BeanReference authenticationFilterSecurityContextRepositoryRef;

	private final List<BeanReference> authenticationProviders;

	private final Map<BeanDefinition, BeanMetadataElement> entryPoints;

	private String loginProcessingUrl = Saml2WebSsoAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI;

	private BeanDefinition saml2WebSsoAuthenticationRequestFilter;

	private BeanDefinition saml2AuthenticationUrlToProviderName;

	Saml2LoginBeanDefinitionParser(List<BeanDefinition> csrfIgnoreRequestMatchers, BeanReference portMapper,
			BeanReference portResolver, BeanReference requestCache, boolean allowSessionCreation,
			BeanReference authenticationManager, BeanReference authenticationFilterSecurityContextRepositoryRef,
			List<BeanReference> authenticationProviders, Map<BeanDefinition, BeanMetadataElement> entryPoints) {
		this.csrfIgnoreRequestMatchers = csrfIgnoreRequestMatchers;
		this.portMapper = portMapper;
		this.portResolver = portResolver;
		this.requestCache = requestCache;
		this.allowSessionCreation = allowSessionCreation;
		this.authenticationManager = authenticationManager;
		this.authenticationFilterSecurityContextRepositoryRef = authenticationFilterSecurityContextRepositoryRef;
		this.authenticationProviders = authenticationProviders;
		this.entryPoints = entryPoints;
	}

	@Override
	public BeanDefinition parse(Element element, ParserContext pc) {
		String loginProcessingUrl = element.getAttribute(ATT_LOGIN_PROCESSING_URL);
		if (StringUtils.hasText(loginProcessingUrl)) {
			this.loginProcessingUrl = loginProcessingUrl;
		}
		BeanDefinition saml2LoginBeanConfig = BeanDefinitionBuilder.rootBeanDefinition(Saml2LoginBeanConfig.class)
				.getBeanDefinition();
		String saml2LoginBeanConfigId = pc.getReaderContext().generateBeanName(saml2LoginBeanConfig);
		pc.registerBeanComponent(new BeanComponentDefinition(saml2LoginBeanConfig, saml2LoginBeanConfigId));
		registerDefaultCsrfOverride();
		BeanMetadataElement relyingPartyRegistrationRepository = Saml2LoginBeanDefinitionParserUtils
				.getRelyingPartyRegistrationRepository(element);
		BeanMetadataElement authenticationRequestRepository = Saml2LoginBeanDefinitionParserUtils
				.getAuthenticationRequestRepository(element);
		BeanMetadataElement authenticationRequestResolver = Saml2LoginBeanDefinitionParserUtils
				.getAuthenticationRequestResolver(element);
		if (authenticationRequestResolver == null) {
			authenticationRequestResolver = Saml2LoginBeanDefinitionParserUtils
					.createDefaultAuthenticationRequestResolver(relyingPartyRegistrationRepository);
		}
		BeanMetadataElement authenticationConverter = Saml2LoginBeanDefinitionParserUtils
				.getAuthenticationConverter(element);
		if (authenticationConverter == null) {
			if (!this.loginProcessingUrl.contains("{registrationId}")) {
				pc.getReaderContext().error("loginProcessingUrl must contain {registrationId} path variable", element);
			}
			authenticationConverter = Saml2LoginBeanDefinitionParserUtils
					.createDefaultAuthenticationConverter(relyingPartyRegistrationRepository);
		}
		// Configure the Saml2WebSsoAuthenticationFilter
		BeanDefinitionBuilder saml2WebSsoAuthenticationFilterBuilder = BeanDefinitionBuilder
				.rootBeanDefinition(Saml2WebSsoAuthenticationFilter.class)
				.addConstructorArgValue(authenticationConverter).addConstructorArgValue(this.loginProcessingUrl)
				.addPropertyValue("authenticationRequestRepository", authenticationRequestRepository);
		resolveLoginPage(element, pc);
		resolveAuthenticationSuccessHandler(element, saml2WebSsoAuthenticationFilterBuilder);
		resolveAuthenticationFailureHandler(element, saml2WebSsoAuthenticationFilterBuilder);
		resolveAuthenticationManager(element, saml2WebSsoAuthenticationFilterBuilder);
		resolveSecurityContextRepository(element, saml2WebSsoAuthenticationFilterBuilder);
		// Configure the Saml2WebSsoAuthenticationRequestFilter
		this.saml2WebSsoAuthenticationRequestFilter = BeanDefinitionBuilder
				.rootBeanDefinition(Saml2WebSsoAuthenticationRequestFilter.class)
				.addConstructorArgValue(authenticationRequestResolver)
				.addPropertyValue("authenticationRequestRepository", authenticationRequestRepository)
				.getBeanDefinition();
		BeanDefinition saml2AuthenticationProvider = Saml2LoginBeanDefinitionParserUtils.createAuthenticationProvider();
		this.authenticationProviders.add(
				new RuntimeBeanReference(pc.getReaderContext().registerWithGeneratedName(saml2AuthenticationProvider)));
		this.saml2AuthenticationUrlToProviderName = BeanDefinitionBuilder.rootBeanDefinition(Map.class)
				.setFactoryMethodOnBean("getAuthenticationUrlToProviderName", saml2LoginBeanConfigId)
				.getBeanDefinition();
		return saml2WebSsoAuthenticationFilterBuilder.getBeanDefinition();
	}

	private void resolveAuthenticationManager(Element element,
			BeanDefinitionBuilder saml2WebSsoAuthenticationFilterBuilder) {
		String authenticationManagerRef = element.getAttribute(ATT_AUTHENTICATION_MANAGER_REF);
		if (StringUtils.hasText(authenticationManagerRef)) {
			saml2WebSsoAuthenticationFilterBuilder.addPropertyReference("authenticationManager",
					authenticationManagerRef);
		}
		else {
			saml2WebSsoAuthenticationFilterBuilder.addPropertyValue("authenticationManager",
					this.authenticationManager);
		}
	}

	private void resolveSecurityContextRepository(Element element,
			BeanDefinitionBuilder saml2WebSsoAuthenticationFilterBuilder) {
		if (this.authenticationFilterSecurityContextRepositoryRef != null) {
			saml2WebSsoAuthenticationFilterBuilder.addPropertyValue("securityContextRepository",
					this.authenticationFilterSecurityContextRepositoryRef);
		}
	}

	private void resolveLoginPage(Element element, ParserContext parserContext) {
		String loginPage = element.getAttribute(ATT_LOGIN_PAGE);
		Object source = parserContext.extractSource(element);
		BeanDefinition saml2LoginAuthenticationEntryPoint = null;
		if (StringUtils.hasText(loginPage)) {
			WebConfigUtils.validateHttpRedirect(loginPage, parserContext, source);
			saml2LoginAuthenticationEntryPoint = BeanDefinitionBuilder
					.rootBeanDefinition(LoginUrlAuthenticationEntryPoint.class).addConstructorArgValue(loginPage)
					.addPropertyValue("portMapper", this.portMapper).addPropertyValue("portResolver", this.portResolver)
					.getBeanDefinition();
		}
		else {
			Map<String, String> identityProviderUrlMap = getIdentityProviderUrlMap(element);
			if (identityProviderUrlMap.size() == 1) {
				String loginUrl = identityProviderUrlMap.entrySet().iterator().next().getKey();
				saml2LoginAuthenticationEntryPoint = BeanDefinitionBuilder
						.rootBeanDefinition(LoginUrlAuthenticationEntryPoint.class).addConstructorArgValue(loginUrl)
						.addPropertyValue("portMapper", this.portMapper)
						.addPropertyValue("portResolver", this.portResolver).getBeanDefinition();
			}
		}
		if (saml2LoginAuthenticationEntryPoint != null) {
			BeanDefinitionBuilder requestMatcherBuilder = BeanDefinitionBuilder
					.rootBeanDefinition(AntPathRequestMatcher.class);
			requestMatcherBuilder.addConstructorArgValue(this.loginProcessingUrl);
			BeanDefinition requestMatcher = requestMatcherBuilder.getBeanDefinition();
			this.entryPoints.put(requestMatcher, saml2LoginAuthenticationEntryPoint);
		}
	}

	private void resolveAuthenticationFailureHandler(Element element,
			BeanDefinitionBuilder saml2WebSsoAuthenticationFilterBuilder) {
		String authenticationFailureHandlerRef = element.getAttribute(ATT_AUTHENTICATION_FAILURE_HANDLER_REF);
		if (StringUtils.hasText(authenticationFailureHandlerRef)) {
			saml2WebSsoAuthenticationFilterBuilder.addPropertyReference("authenticationFailureHandler",
					authenticationFailureHandlerRef);
		}
		else {
			BeanDefinitionBuilder failureHandlerBuilder = BeanDefinitionBuilder.rootBeanDefinition(
					"org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler");
			failureHandlerBuilder.addConstructorArgValue(
					DEFAULT_LOGIN_URI + "?" + DefaultLoginPageGeneratingFilter.ERROR_PARAMETER_NAME);
			failureHandlerBuilder.addPropertyValue("allowSessionCreation", this.allowSessionCreation);
			saml2WebSsoAuthenticationFilterBuilder.addPropertyValue("authenticationFailureHandler",
					failureHandlerBuilder.getBeanDefinition());
		}
	}

	private void resolveAuthenticationSuccessHandler(Element element,
			BeanDefinitionBuilder saml2WebSsoAuthenticationFilterBuilder) {
		String authenticationSuccessHandlerRef = element.getAttribute(ATT_AUTHENTICATION_SUCCESS_HANDLER_REF);
		if (StringUtils.hasText(authenticationSuccessHandlerRef)) {
			saml2WebSsoAuthenticationFilterBuilder.addPropertyReference("authenticationSuccessHandler",
					authenticationSuccessHandlerRef);
		}
		else {
			BeanDefinitionBuilder successHandlerBuilder = BeanDefinitionBuilder.rootBeanDefinition(
					"org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler")
					.addPropertyValue("requestCache", this.requestCache);
			saml2WebSsoAuthenticationFilterBuilder.addPropertyValue("authenticationSuccessHandler",
					successHandlerBuilder.getBeanDefinition());
		}
	}

	private void registerDefaultCsrfOverride() {
		BeanDefinitionBuilder requestMatcherBuilder = BeanDefinitionBuilder
				.rootBeanDefinition(AntPathRequestMatcher.class);
		requestMatcherBuilder.addConstructorArgValue(this.loginProcessingUrl);
		BeanDefinition requestMatcher = requestMatcherBuilder.getBeanDefinition();
		this.csrfIgnoreRequestMatchers.add(requestMatcher);
	}

	private Map<String, String> getIdentityProviderUrlMap(Element element) {
		Map<String, String> idps = new LinkedHashMap<>();
		Element relyingPartyRegistrationsElt = DomUtils.getChildElementByTagName(
				element.getOwnerDocument().getDocumentElement(), Elements.RELYING_PARTY_REGISTRATIONS);
		String authenticationRequestProcessingUrl = DEFAULT_AUTHENTICATION_REQUEST_PROCESSING_URL;
		if (relyingPartyRegistrationsElt != null) {
			List<Element> relyingPartyRegList = DomUtils.getChildElementsByTagName(relyingPartyRegistrationsElt,
					ELT_RELYING_PARTY_REGISTRATION);
			for (Element relyingPartyReg : relyingPartyRegList) {
				String registrationId = relyingPartyReg.getAttribute(ELT_REGISTRATION_ID);
				idps.put(authenticationRequestProcessingUrl.replace("{registrationId}", registrationId),
						registrationId);
			}
		}
		return idps;
	}

	BeanDefinition getSaml2WebSsoAuthenticationRequestFilter() {
		return this.saml2WebSsoAuthenticationRequestFilter;
	}

	BeanDefinition getSaml2AuthenticationUrlToProviderName() {
		return this.saml2AuthenticationUrlToProviderName;
	}

	/**
	 * Wrapper bean class to provide configuration from applicationContext
	 */
	public static class Saml2LoginBeanConfig implements ApplicationContextAware {

		private ApplicationContext context;

		@SuppressWarnings({ "unchecked", "unused" })
		Map<String, String> getAuthenticationUrlToProviderName() {
			Iterable<RelyingPartyRegistration> relyingPartyRegistrations = null;
			RelyingPartyRegistrationRepository relyingPartyRegistrationRepository = this.context
					.getBean(RelyingPartyRegistrationRepository.class);
			ResolvableType type = ResolvableType.forInstance(relyingPartyRegistrationRepository).as(Iterable.class);
			if (type != ResolvableType.NONE
					&& RelyingPartyRegistration.class.isAssignableFrom(type.resolveGenerics()[0])) {
				relyingPartyRegistrations = (Iterable<RelyingPartyRegistration>) relyingPartyRegistrationRepository;
			}
			if (relyingPartyRegistrations == null) {
				return Collections.emptyMap();
			}
			String authenticationRequestProcessingUrl = DEFAULT_AUTHENTICATION_REQUEST_PROCESSING_URL;
			Map<String, String> saml2AuthenticationUrlToProviderName = new HashMap<>();
			relyingPartyRegistrations.forEach((registration) -> saml2AuthenticationUrlToProviderName.put(
					authenticationRequestProcessingUrl.replace("{registrationId}", registration.getRegistrationId()),
					registration.getRegistrationId()));
			return saml2AuthenticationUrlToProviderName;
		}

		@Override
		public void setApplicationContext(ApplicationContext context) throws BeansException {
			this.context = context;
		}

	}

}
