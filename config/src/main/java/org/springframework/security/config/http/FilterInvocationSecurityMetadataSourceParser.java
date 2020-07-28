/*
 * Copyright 2002-2016 the original author or authors.
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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.w3c.dom.Element;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.AbstractBeanDefinitionParser;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.config.Elements;
import org.springframework.security.web.access.expression.DefaultWebSecurityExpressionHandler;
import org.springframework.security.web.access.expression.ExpressionBasedFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.util.StringUtils;
import org.springframework.util.xml.DomUtils;

/**
 * Allows for convenient creation of a {@link FilterInvocationSecurityMetadataSource} bean
 * for use with a FilterSecurityInterceptor.
 *
 * @author Luke Taylor
 */
public class FilterInvocationSecurityMetadataSourceParser implements BeanDefinitionParser {

	private static final String ATT_USE_EXPRESSIONS = "use-expressions";

	private static final String ATT_HTTP_METHOD = "method";

	private static final String ATT_PATTERN = "pattern";

	private static final String ATT_ACCESS = "access";

	private static final String ATT_SERVLET_PATH = "servlet-path";

	private static final Log logger = LogFactory.getLog(FilterInvocationSecurityMetadataSourceParser.class);

	@Override
	public BeanDefinition parse(Element element, ParserContext parserContext) {
		List<Element> interceptUrls = DomUtils.getChildElementsByTagName(element, Elements.INTERCEPT_URL);

		// Check for attributes that aren't allowed in this context
		for (Element elt : interceptUrls) {
			if (StringUtils.hasLength(elt.getAttribute(HttpSecurityBeanDefinitionParser.ATT_REQUIRES_CHANNEL))) {
				parserContext.getReaderContext().error("The attribute '"
						+ HttpSecurityBeanDefinitionParser.ATT_REQUIRES_CHANNEL + "' isn't allowed here.", elt);
			}

			if (StringUtils.hasLength(elt.getAttribute(HttpSecurityBeanDefinitionParser.ATT_FILTERS))) {
				parserContext.getReaderContext().error(
						"The attribute '" + HttpSecurityBeanDefinitionParser.ATT_FILTERS + "' isn't allowed here.",
						elt);
			}

			if (StringUtils.hasLength(elt.getAttribute(ATT_SERVLET_PATH))) {
				parserContext.getReaderContext().error("The attribute '" + ATT_SERVLET_PATH + "' isn't allowed here.",
						elt);
			}
		}

		BeanDefinition mds = createSecurityMetadataSource(interceptUrls, false, element, parserContext);

		String id = element.getAttribute(AbstractBeanDefinitionParser.ID_ATTRIBUTE);

		if (StringUtils.hasText(id)) {
			parserContext.registerComponent(new BeanComponentDefinition(mds, id));
			parserContext.getRegistry().registerBeanDefinition(id, mds);
		}

		return mds;
	}

	static RootBeanDefinition createSecurityMetadataSource(List<Element> interceptUrls, boolean addAllAuth,
			Element httpElt, ParserContext pc) {
		MatcherType matcherType = MatcherType.fromElement(httpElt);
		boolean useExpressions = isUseExpressions(httpElt);

		ManagedMap<BeanMetadataElement, BeanDefinition> requestToAttributesMap = parseInterceptUrlsForFilterInvocationRequestMap(
				matcherType, interceptUrls, useExpressions, addAllAuth, pc);
		BeanDefinitionBuilder fidsBuilder;

		if (useExpressions) {
			Element expressionHandlerElt = DomUtils.getChildElementByTagName(httpElt, Elements.EXPRESSION_HANDLER);
			String expressionHandlerRef = expressionHandlerElt == null ? null
					: expressionHandlerElt.getAttribute("ref");

			if (StringUtils.hasText(expressionHandlerRef)) {
				logger.info(
						"Using bean '" + expressionHandlerRef + "' as web SecurityExpressionHandler implementation");
			}
			else {
				expressionHandlerRef = registerDefaultExpressionHandler(pc);
			}

			fidsBuilder = BeanDefinitionBuilder
					.rootBeanDefinition(ExpressionBasedFilterInvocationSecurityMetadataSource.class);
			fidsBuilder.addConstructorArgValue(requestToAttributesMap);
			fidsBuilder.addConstructorArgReference(expressionHandlerRef);
		}
		else {
			fidsBuilder = BeanDefinitionBuilder.rootBeanDefinition(DefaultFilterInvocationSecurityMetadataSource.class);
			fidsBuilder.addConstructorArgValue(requestToAttributesMap);
		}

		fidsBuilder.getRawBeanDefinition().setSource(pc.extractSource(httpElt));

		return (RootBeanDefinition) fidsBuilder.getBeanDefinition();
	}

	static String registerDefaultExpressionHandler(ParserContext pc) {
		BeanDefinition expressionHandler = GrantedAuthorityDefaultsParserUtils.registerWithDefaultRolePrefix(pc,
				DefaultWebSecurityExpressionHandlerBeanFactory.class);
		String expressionHandlerRef = pc.getReaderContext().generateBeanName(expressionHandler);
		pc.registerBeanComponent(new BeanComponentDefinition(expressionHandler, expressionHandlerRef));

		return expressionHandlerRef;
	}

	static boolean isUseExpressions(Element elt) {
		String useExpressions = elt.getAttribute(ATT_USE_EXPRESSIONS);
		return !StringUtils.hasText(useExpressions) || "true".equals(useExpressions);
	}

	private static ManagedMap<BeanMetadataElement, BeanDefinition> parseInterceptUrlsForFilterInvocationRequestMap(
			MatcherType matcherType, List<Element> urlElts, boolean useExpressions, boolean addAuthenticatedAll,
			ParserContext parserContext) {

		ManagedMap<BeanMetadataElement, BeanDefinition> filterInvocationDefinitionMap = new ManagedMap<>();

		for (Element urlElt : urlElts) {
			String access = urlElt.getAttribute(ATT_ACCESS);
			if (!StringUtils.hasText(access)) {
				continue;
			}

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
						ATT_SERVLET_PATH + " is not applicable for request-matcher: '" + matcherType.name() + "'",
						urlElt);
			}

			BeanMetadataElement matcher = hasMatcherRef ? new RuntimeBeanReference(matcherRef)
					: matcherType.createMatcher(parserContext, path, method, servletPath);
			BeanDefinitionBuilder attributeBuilder = BeanDefinitionBuilder.rootBeanDefinition(SecurityConfig.class);

			if (useExpressions) {
				logger.info("Creating access control expression attribute '" + access + "' for " + path);
				// The single expression will be parsed later by the
				// ExpressionBasedFilterInvocationSecurityMetadataSource
				attributeBuilder.addConstructorArgValue(new String[] { access });
				attributeBuilder.setFactoryMethod("createList");

			}
			else {
				attributeBuilder.addConstructorArgValue(access);
				attributeBuilder.setFactoryMethod("createListFromCommaDelimitedString");
			}

			if (filterInvocationDefinitionMap.containsKey(matcher)) {
				logger.warn("Duplicate URL defined: " + path + ". The original attribute values will be overwritten");
			}

			filterInvocationDefinitionMap.put(matcher, attributeBuilder.getBeanDefinition());
		}

		if (addAuthenticatedAll && filterInvocationDefinitionMap.isEmpty()) {

			BeanDefinition matcher = matcherType.createMatcher(parserContext, "/**", null);
			BeanDefinitionBuilder attributeBuilder = BeanDefinitionBuilder.rootBeanDefinition(SecurityConfig.class);
			attributeBuilder.addConstructorArgValue(new String[] { "authenticated" });
			attributeBuilder.setFactoryMethod("createList");
			filterInvocationDefinitionMap.put(matcher, attributeBuilder.getBeanDefinition());
		}

		return filterInvocationDefinitionMap;
	}

	static class DefaultWebSecurityExpressionHandlerBeanFactory
			extends GrantedAuthorityDefaultsParserUtils.AbstractGrantedAuthorityDefaultsBeanFactory {

		private DefaultWebSecurityExpressionHandler handler = new DefaultWebSecurityExpressionHandler();

		@Override
		public DefaultWebSecurityExpressionHandler getBean() {
			this.handler.setDefaultRolePrefix(this.rolePrefix);
			return this.handler;
		}

	}

}
