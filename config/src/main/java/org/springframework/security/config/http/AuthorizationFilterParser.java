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

import java.util.List;
import java.util.Map;

import io.micrometer.observation.ObservationRegistry;
import jakarta.servlet.http.HttpServletRequest;
import org.w3c.dom.Element;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.FactoryBean;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.factory.xml.XmlReaderContext;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.ObservationAuthorizationManager;
import org.springframework.security.config.Elements;
import org.springframework.security.web.access.expression.DefaultHttpSecurityExpressionHandler;
import org.springframework.security.web.access.expression.WebExpressionAuthorizationManager;
import org.springframework.security.web.access.intercept.AuthorizationFilter;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.security.web.access.intercept.RequestMatcherDelegatingAuthorizationManager;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;

class AuthorizationFilterParser implements BeanDefinitionParser {

	private static final String ATT_USE_EXPRESSIONS = "use-expressions";

	private static final String ATT_ACCESS_DECISION_MANAGER_REF = "access-decision-manager-ref";

	private static final String ATT_OBSERVATION_REGISTRY_REF = "observation-registry-ref";

	private static final String ATT_HTTP_METHOD = "method";

	private static final String ATT_PATTERN = "pattern";

	private static final String ATT_ACCESS = "access";

	private static final String ATT_SERVLET_PATH = "servlet-path";

	private static final String ATT_FILTER_ALL_DISPATCHER_TYPES = "filter-all-dispatcher-types";

	private String authorizationManagerRef;

	private final BeanMetadataElement securityContextHolderStrategy;

	AuthorizationFilterParser(BeanMetadataElement securityContextHolderStrategy) {
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	@Override
	public BeanDefinition parse(Element element, ParserContext parserContext) {
		if (!isUseExpressions(element)) {
			parserContext.getReaderContext().error("AuthorizationManager must be used with `use-expressions=\"true\"",
					element);
			return null;
		}
		if (StringUtils.hasText(element.getAttribute(ATT_ACCESS_DECISION_MANAGER_REF))) {
			parserContext.getReaderContext().error(
					"AuthorizationManager cannot be used in conjunction with `access-decision-manager-ref`", element);
			return null;
		}
		this.authorizationManagerRef = createAuthorizationManager(element, parserContext);
		BeanDefinitionBuilder filterBuilder = BeanDefinitionBuilder.rootBeanDefinition(AuthorizationFilter.class);
		filterBuilder.getRawBeanDefinition().setSource(parserContext.extractSource(element));
		filterBuilder.addConstructorArgReference(this.authorizationManagerRef);
		if ("false".equals(element.getAttribute(ATT_FILTER_ALL_DISPATCHER_TYPES))) {
			filterBuilder.addPropertyValue("shouldFilterAllDispatcherTypes", Boolean.FALSE);
		}
		BeanDefinition filter = filterBuilder
				.addPropertyValue("securityContextHolderStrategy", this.securityContextHolderStrategy)
				.getBeanDefinition();
		String id = element.getAttribute(AbstractBeanDefinitionParser.ID_ATTRIBUTE);
		if (StringUtils.hasText(id)) {
			parserContext.registerComponent(new BeanComponentDefinition(filter, id));
			parserContext.getRegistry().registerBeanDefinition(id, filter);
		}
		return filter;
	}

	String getAuthorizationManagerRef() {
		return this.authorizationManagerRef;
	}

	private String createAuthorizationManager(Element element, ParserContext parserContext) {
		XmlReaderContext context = parserContext.getReaderContext();
		String authorizationManagerRef = element.getAttribute("authorization-manager-ref");
		if (StringUtils.hasText(authorizationManagerRef)) {
			return authorizationManagerRef;
		}
		Element expressionHandlerElt = DomUtils.getChildElementByTagName(element, Elements.EXPRESSION_HANDLER);
		String expressionHandlerRef = (expressionHandlerElt != null) ? expressionHandlerElt.getAttribute("ref") : null;
		if (expressionHandlerRef == null) {
			expressionHandlerRef = registerDefaultExpressionHandler(parserContext);
		}
		MatcherType matcherType = MatcherType.fromElementOrMvc(element);
		ManagedMap<BeanMetadataElement, BeanDefinition> matcherToExpression = new ManagedMap<>();
		List<Element> interceptMessages = DomUtils.getChildElementsByTagName(element, Elements.INTERCEPT_URL);
		for (Element interceptMessage : interceptMessages) {
			String accessExpression = interceptMessage.getAttribute(ATT_ACCESS);
			BeanDefinitionBuilder authorizationManager = BeanDefinitionBuilder
					.rootBeanDefinition(WebExpressionAuthorizationManager.class);
			authorizationManager.addPropertyReference("expressionHandler", expressionHandlerRef);
			authorizationManager.addConstructorArgValue(accessExpression);
			BeanMetadataElement matcher = createMatcher(matcherType, interceptMessage, parserContext);
			matcherToExpression.put(matcher, authorizationManager.getBeanDefinition());
		}
		BeanDefinitionBuilder mds = BeanDefinitionBuilder
				.rootBeanDefinition(RequestMatcherDelegatingAuthorizationManagerFactory.class)
				.addPropertyValue("requestMatcherMap", matcherToExpression)
				.addPropertyValue("observationRegistry", getObservationRegistry(element));
		return context.registerWithGeneratedName(mds.getBeanDefinition());
	}

	private BeanMetadataElement createMatcher(MatcherType matcherType, Element urlElt, ParserContext parserContext) {
		String path = urlElt.getAttribute(ATT_PATTERN);
		String matcherRef = urlElt.getAttribute(HttpSecurityBeanDefinitionParser.ATT_REQUEST_MATCHER_REF);
		boolean hasMatcherRef = StringUtils.hasText(matcherRef);
		if (!hasMatcherRef && !StringUtils.hasText(path)) {
			parserContext.getReaderContext().error("path attribute cannot be empty or null", urlElt);
		}
		String method = urlElt.getAttribute(ATT_HTTP_METHOD);
		if (!StringUtils.hasText(method)) {
			method = null;
		}
		String servletPath = urlElt.getAttribute(ATT_SERVLET_PATH);
		if (!StringUtils.hasText(servletPath)) {
			servletPath = null;
		}
		else if (!MatcherType.mvc.equals(matcherType)) {
			parserContext.getReaderContext().error(
					ATT_SERVLET_PATH + " is not applicable for request-matcher: '" + matcherType.name() + "'", urlElt);
		}
		return hasMatcherRef ? new RuntimeBeanReference(matcherRef)
				: matcherType.createMatcher(parserContext, path, method, servletPath);
	}

	String registerDefaultExpressionHandler(ParserContext pc) {
		BeanDefinition expressionHandler = GrantedAuthorityDefaultsParserUtils.registerWithDefaultRolePrefix(pc,
				DefaultWebSecurityExpressionHandlerBeanFactory.class);
		String expressionHandlerRef = pc.getReaderContext().generateBeanName(expressionHandler);
		pc.registerBeanComponent(new BeanComponentDefinition(expressionHandler, expressionHandlerRef));
		return expressionHandlerRef;
	}

	boolean isUseExpressions(Element elt) {
		String useExpressions = elt.getAttribute(ATT_USE_EXPRESSIONS);
		return !StringUtils.hasText(useExpressions) || "true".equals(useExpressions);
	}

	private BeanMetadataElement getObservationRegistry(Element methodSecurityElmt) {
		String holderStrategyRef = methodSecurityElmt.getAttribute(ATT_OBSERVATION_REGISTRY_REF);
		if (StringUtils.hasText(holderStrategyRef)) {
			return new RuntimeBeanReference(holderStrategyRef);
		}
		return BeanDefinitionBuilder.rootBeanDefinition(ObservationRegistryFactory.class).getBeanDefinition();
	}

	public static final class RequestMatcherDelegatingAuthorizationManagerFactory
			implements FactoryBean<AuthorizationManager<HttpServletRequest>> {

		private Map<RequestMatcher, AuthorizationManager<RequestAuthorizationContext>> beans;

		private ObservationRegistry observationRegistry = ObservationRegistry.NOOP;

		@Override
		public AuthorizationManager<HttpServletRequest> getObject() throws Exception {
			RequestMatcherDelegatingAuthorizationManager.Builder builder = RequestMatcherDelegatingAuthorizationManager
					.builder();
			for (Map.Entry<RequestMatcher, AuthorizationManager<RequestAuthorizationContext>> entry : this.beans
					.entrySet()) {
				builder.add(entry.getKey(), entry.getValue());
			}
			AuthorizationManager<HttpServletRequest> manager = builder.build();
			if (!this.observationRegistry.isNoop()) {
				return new ObservationAuthorizationManager<>(this.observationRegistry, manager);
			}
			return manager;
		}

		@Override
		public Class<?> getObjectType() {
			return AuthorizationManager.class;
		}

		public void setRequestMatcherMap(Map<RequestMatcher, AuthorizationManager<RequestAuthorizationContext>> beans) {
			this.beans = beans;
		}

		public void setObservationRegistry(ObservationRegistry observationRegistry) {
			this.observationRegistry = observationRegistry;
		}

	}

	static class DefaultWebSecurityExpressionHandlerBeanFactory
			extends GrantedAuthorityDefaultsParserUtils.AbstractGrantedAuthorityDefaultsBeanFactory {

		private DefaultHttpSecurityExpressionHandler handler = new DefaultHttpSecurityExpressionHandler();

		@Override
		public DefaultHttpSecurityExpressionHandler getBean() {
			if (this.rolePrefix != null) {
				this.handler.setDefaultRolePrefix(this.rolePrefix);
			}
			return this.handler;
		}

	}

	static class ObservationRegistryFactory implements FactoryBean<ObservationRegistry> {

		@Override
		public ObservationRegistry getObject() throws Exception {
			return ObservationRegistry.NOOP;
		}

		@Override
		public Class<?> getObjectType() {
			return ObservationRegistry.class;
		}

	}

}
