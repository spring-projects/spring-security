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

import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;

import jakarta.servlet.http.HttpServletRequest;
import org.w3c.dom.Element;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.web.DefaultRelyingPartyRegistrationResolver;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestFilter;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutResponseFilter;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2RelyingPartyInitiatedLogoutSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessEventPublishingLogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * SAML 2.0 Single Logout {@link BeanDefinitionParser}
 *
 * @author Marcus da Coregio
 * @since 5.7
 */
final class Saml2LogoutBeanDefinitionParser implements BeanDefinitionParser {

	private static final String ATT_LOGOUT_REQUEST_URL = "logout-request-url";

	private static final String ATT_LOGOUT_RESPONSE_URL = "logout-response-url";

	private static final String ATT_LOGOUT_URL = "logout-url";

	private List<BeanMetadataElement> logoutHandlers;

	private String logoutUrl = "/logout";

	private String logoutRequestUrl = "/logout/saml2/slo";

	private String logoutResponseUrl = "/logout/saml2/slo";

	private BeanMetadataElement logoutSuccessHandler;

	private BeanDefinition logoutRequestFilter;

	private BeanDefinition logoutResponseFilter;

	private BeanDefinition logoutFilter;

	private BeanMetadataElement authenticationFilterSecurityContextHolderStrategy;

	Saml2LogoutBeanDefinitionParser(ManagedList<BeanMetadataElement> logoutHandlers,
			BeanMetadataElement logoutSuccessHandler,
			BeanMetadataElement authenticationFilterSecurityContextHolderStrategy) {
		this.logoutHandlers = logoutHandlers;
		this.logoutSuccessHandler = logoutSuccessHandler;
		this.authenticationFilterSecurityContextHolderStrategy = authenticationFilterSecurityContextHolderStrategy;
	}

	@Override
	public BeanDefinition parse(Element element, ParserContext pc) {
		String logoutUrl = element.getAttribute(ATT_LOGOUT_URL);
		if (StringUtils.hasText(logoutUrl)) {
			this.logoutUrl = logoutUrl;
		}
		String logoutRequestUrl = element.getAttribute(ATT_LOGOUT_REQUEST_URL);
		if (StringUtils.hasText(logoutRequestUrl)) {
			this.logoutRequestUrl = logoutRequestUrl;
		}
		String logoutResponseUrl = element.getAttribute(ATT_LOGOUT_RESPONSE_URL);
		if (StringUtils.hasText(logoutResponseUrl)) {
			this.logoutResponseUrl = logoutResponseUrl;
		}
		WebConfigUtils.validateHttpRedirect(this.logoutUrl, pc, element);
		WebConfigUtils.validateHttpRedirect(this.logoutRequestUrl, pc, element);
		WebConfigUtils.validateHttpRedirect(this.logoutResponseUrl, pc, element);
		if (CollectionUtils.isEmpty(this.logoutHandlers)) {
			this.logoutHandlers = createDefaultLogoutHandlers();
		}
		if (this.logoutSuccessHandler == null) {
			this.logoutSuccessHandler = createDefaultLogoutSuccessHandler();
		}
		BeanMetadataElement relyingPartyRegistrationRepository = Saml2LogoutBeanDefinitionParserUtils
				.getRelyingPartyRegistrationRepository(element);
		BeanMetadataElement registrations = BeanDefinitionBuilder
				.rootBeanDefinition(DefaultRelyingPartyRegistrationResolver.class)
				.addConstructorArgValue(relyingPartyRegistrationRepository).getBeanDefinition();
		BeanMetadataElement logoutResponseResolver = Saml2LogoutBeanDefinitionParserUtils
				.getLogoutResponseResolver(element, registrations);
		BeanMetadataElement logoutRequestValidator = Saml2LogoutBeanDefinitionParserUtils
				.getLogoutRequestValidator(element);
		BeanMetadataElement logoutRequestMatcher = createSaml2LogoutRequestMatcher();
		this.logoutRequestFilter = BeanDefinitionBuilder.rootBeanDefinition(Saml2LogoutRequestFilter.class)
				.addConstructorArgValue(registrations).addConstructorArgValue(logoutRequestValidator)
				.addConstructorArgValue(logoutResponseResolver).addConstructorArgValue(this.logoutHandlers)
				.addPropertyValue("logoutRequestMatcher", logoutRequestMatcher)
				.addPropertyValue("securityContextHolderStrategy",
						this.authenticationFilterSecurityContextHolderStrategy)
				.getBeanDefinition();
		BeanMetadataElement logoutResponseValidator = Saml2LogoutBeanDefinitionParserUtils
				.getLogoutResponseValidator(element);
		BeanMetadataElement logoutRequestRepository = Saml2LogoutBeanDefinitionParserUtils
				.getLogoutRequestRepository(element);
		BeanMetadataElement logoutResponseMatcher = createSaml2LogoutResponseMatcher();
		this.logoutResponseFilter = BeanDefinitionBuilder.rootBeanDefinition(Saml2LogoutResponseFilter.class)
				.addConstructorArgValue(registrations).addConstructorArgValue(logoutResponseValidator)
				.addConstructorArgValue(this.logoutSuccessHandler)
				.addPropertyValue("logoutRequestMatcher", logoutResponseMatcher)
				.addPropertyValue("logoutRequestRepository", logoutRequestRepository).getBeanDefinition();
		BeanMetadataElement logoutRequestResolver = Saml2LogoutBeanDefinitionParserUtils
				.getLogoutRequestResolver(element, registrations);
		BeanMetadataElement saml2LogoutRequestSuccessHandler = BeanDefinitionBuilder
				.rootBeanDefinition(Saml2RelyingPartyInitiatedLogoutSuccessHandler.class)
				.addConstructorArgValue(logoutRequestResolver).getBeanDefinition();
		this.logoutFilter = BeanDefinitionBuilder.rootBeanDefinition(LogoutFilter.class)
				.addConstructorArgValue(saml2LogoutRequestSuccessHandler).addConstructorArgValue(this.logoutHandlers)
				.addPropertyValue("logoutRequestMatcher", createLogoutRequestMatcher()).getBeanDefinition();
		return null;
	}

	private static List<BeanMetadataElement> createDefaultLogoutHandlers() {
		List<BeanMetadataElement> handlers = new ManagedList<>();
		handlers.add(BeanDefinitionBuilder.rootBeanDefinition(SecurityContextLogoutHandler.class).getBeanDefinition());
		handlers.add(BeanDefinitionBuilder.rootBeanDefinition(LogoutSuccessEventPublishingLogoutHandler.class)
				.getBeanDefinition());
		return handlers;
	}

	private static BeanMetadataElement createDefaultLogoutSuccessHandler() {
		return BeanDefinitionBuilder.rootBeanDefinition(SimpleUrlLogoutSuccessHandler.class)
				.addPropertyValue("defaultTargetUrl", "/login?logout").getBeanDefinition();
	}

	private BeanMetadataElement createLogoutRequestMatcher() {
		BeanMetadataElement logoutMatcher = BeanDefinitionBuilder.rootBeanDefinition(AntPathRequestMatcher.class)
				.addConstructorArgValue(this.logoutUrl).addConstructorArgValue("POST").getBeanDefinition();
		BeanMetadataElement saml2Matcher = BeanDefinitionBuilder.rootBeanDefinition(Saml2RequestMatcher.class)
				.addPropertyValue("securityContextHolderStrategy",
						this.authenticationFilterSecurityContextHolderStrategy)
				.getBeanDefinition();
		return BeanDefinitionBuilder.rootBeanDefinition(AndRequestMatcher.class)
				.addConstructorArgValue(toManagedList(logoutMatcher, saml2Matcher)).getBeanDefinition();
	}

	private BeanMetadataElement createSaml2LogoutRequestMatcher() {
		BeanMetadataElement logoutRequestMatcher = BeanDefinitionBuilder.rootBeanDefinition(AntPathRequestMatcher.class)
				.addConstructorArgValue(this.logoutRequestUrl).getBeanDefinition();
		BeanMetadataElement saml2RequestMatcher = BeanDefinitionBuilder
				.rootBeanDefinition(ParameterRequestMatcher.class).addConstructorArgValue("SAMLRequest")
				.getBeanDefinition();
		return BeanDefinitionBuilder.rootBeanDefinition(AndRequestMatcher.class)
				.addConstructorArgValue(toManagedList(logoutRequestMatcher, saml2RequestMatcher)).getBeanDefinition();
	}

	private BeanMetadataElement createSaml2LogoutResponseMatcher() {
		BeanMetadataElement logoutResponseMatcher = BeanDefinitionBuilder
				.rootBeanDefinition(AntPathRequestMatcher.class).addConstructorArgValue(this.logoutResponseUrl)
				.getBeanDefinition();
		BeanMetadataElement saml2ResponseMatcher = BeanDefinitionBuilder
				.rootBeanDefinition(ParameterRequestMatcher.class).addConstructorArgValue("SAMLResponse")
				.getBeanDefinition();
		return BeanDefinitionBuilder.rootBeanDefinition(AndRequestMatcher.class)
				.addConstructorArgValue(toManagedList(logoutResponseMatcher, saml2ResponseMatcher)).getBeanDefinition();
	}

	private static List<BeanMetadataElement> toManagedList(BeanMetadataElement... elements) {
		List<BeanMetadataElement> managedList = new ManagedList<>();
		managedList.addAll(Arrays.asList(elements));
		return managedList;
	}

	BeanDefinition getLogoutRequestFilter() {
		return this.logoutRequestFilter;
	}

	BeanDefinition getLogoutResponseFilter() {
		return this.logoutResponseFilter;
	}

	BeanDefinition getLogoutFilter() {
		return this.logoutFilter;
	}

	private static class ParameterRequestMatcher implements RequestMatcher {

		Predicate<String> test = Objects::nonNull;

		String name;

		ParameterRequestMatcher(String name) {
			this.name = name;
		}

		@Override
		public boolean matches(HttpServletRequest request) {
			return this.test.test(request.getParameter(this.name));
		}

	}

	public static class Saml2RequestMatcher implements RequestMatcher {

		private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
				.getContextHolderStrategy();

		@Override
		public boolean matches(HttpServletRequest request) {
			Authentication authentication = this.securityContextHolderStrategy.getContext().getAuthentication();
			if (authentication == null) {
				return false;
			}
			return authentication.getPrincipal() instanceof Saml2AuthenticatedPrincipal;
		}

		public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
			this.securityContextHolderStrategy = securityContextHolderStrategy;
		}

	}

}
