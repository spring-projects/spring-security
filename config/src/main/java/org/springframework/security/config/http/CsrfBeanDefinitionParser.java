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
import java.util.HashSet;
import java.util.List;
import javax.servlet.http.HttpServletRequest;

import org.w3c.dom.Element;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.parsing.BeanComponentDefinition;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.support.ManagedMap;
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.DelegatingAccessDeniedHandler;
import org.springframework.security.web.csrf.CsrfAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfLogoutHandler;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.csrf.LazyCsrfTokenRepository;
import org.springframework.security.web.csrf.MissingCsrfTokenException;
import org.springframework.security.web.servlet.support.csrf.CsrfRequestDataValueProcessor;
import org.springframework.security.web.session.InvalidSessionAccessDeniedHandler;
import org.springframework.security.web.session.InvalidSessionStrategy;
import org.springframework.security.web.util.matcher.AndRequestMatcher;
import org.springframework.security.web.util.matcher.NegatedRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;

/**
 * Parser for the {@code CsrfFilter}.
 *
 * @author Rob Winch
 * @author Ankur Pathak
 * @since 3.2
 */
public class CsrfBeanDefinitionParser implements BeanDefinitionParser {

	private static final String REQUEST_DATA_VALUE_PROCESSOR = "requestDataValueProcessor";

	private static final String DISPATCHER_SERVLET_CLASS_NAME = "org.springframework.web.servlet.DispatcherServlet";

	private static final String ATT_MATCHER = "request-matcher-ref";

	private static final String ATT_REPOSITORY = "token-repository-ref";

	private String csrfRepositoryRef;

	private BeanDefinition csrfFilter;

	private String requestMatcherRef;

	@Override
	public BeanDefinition parse(Element element, ParserContext pc) {
		boolean disabled = element != null && "true".equals(element.getAttribute("disabled"));
		if (disabled) {
			return null;
		}
		boolean webmvcPresent = ClassUtils.isPresent(DISPATCHER_SERVLET_CLASS_NAME, getClass().getClassLoader());
		if (webmvcPresent) {
			if (!pc.getRegistry().containsBeanDefinition(REQUEST_DATA_VALUE_PROCESSOR)) {
				RootBeanDefinition beanDefinition = new RootBeanDefinition(CsrfRequestDataValueProcessor.class);
				BeanComponentDefinition componentDefinition = new BeanComponentDefinition(beanDefinition,
						REQUEST_DATA_VALUE_PROCESSOR);
				pc.registerBeanComponent(componentDefinition);
			}
		}

		if (element != null) {
			this.csrfRepositoryRef = element.getAttribute(ATT_REPOSITORY);
			this.requestMatcherRef = element.getAttribute(ATT_MATCHER);
		}

		if (!StringUtils.hasText(this.csrfRepositoryRef)) {

			RootBeanDefinition csrfTokenRepository = new RootBeanDefinition(HttpSessionCsrfTokenRepository.class);
			BeanDefinitionBuilder lazyTokenRepository = BeanDefinitionBuilder
					.rootBeanDefinition(LazyCsrfTokenRepository.class);
			lazyTokenRepository.addConstructorArgValue(csrfTokenRepository);
			this.csrfRepositoryRef = pc.getReaderContext().generateBeanName(lazyTokenRepository.getBeanDefinition());
			pc.registerBeanComponent(
					new BeanComponentDefinition(lazyTokenRepository.getBeanDefinition(), this.csrfRepositoryRef));
		}

		BeanDefinitionBuilder builder = BeanDefinitionBuilder.rootBeanDefinition(CsrfFilter.class);
		builder.addConstructorArgReference(this.csrfRepositoryRef);

		if (StringUtils.hasText(this.requestMatcherRef)) {
			builder.addPropertyReference("requireCsrfProtectionMatcher", this.requestMatcherRef);
		}

		this.csrfFilter = builder.getBeanDefinition();
		return this.csrfFilter;
	}

	/**
	 * Populate the AccessDeniedHandler on the {@link CsrfFilter}
	 * @param invalidSessionStrategy the {@link InvalidSessionStrategy} to use
	 * @param defaultDeniedHandler the {@link AccessDeniedHandler} to use
	 */
	void initAccessDeniedHandler(BeanDefinition invalidSessionStrategy, BeanMetadataElement defaultDeniedHandler) {
		BeanMetadataElement accessDeniedHandler = createAccessDeniedHandler(invalidSessionStrategy,
				defaultDeniedHandler);
		this.csrfFilter.getPropertyValues().addPropertyValue("accessDeniedHandler", accessDeniedHandler);
	}

	/**
	 * Creates the {@link AccessDeniedHandler} from the result of
	 * {@link #getDefaultAccessDeniedHandler(HttpSecurityBuilder)} and
	 * {@link #getInvalidSessionStrategy(HttpSecurityBuilder)}. If
	 * {@link #getInvalidSessionStrategy(HttpSecurityBuilder)} is non-null, then a
	 * {@link DelegatingAccessDeniedHandler} is used in combination with
	 * {@link InvalidSessionAccessDeniedHandler} and the
	 * {@link #getDefaultAccessDeniedHandler(HttpSecurityBuilder)}. Otherwise, only
	 * {@link #getDefaultAccessDeniedHandler(HttpSecurityBuilder)} is used.
	 * @param invalidSessionStrategy the {@link InvalidSessionStrategy} to use
	 * @param defaultDeniedHandler the {@link AccessDeniedHandler} to use
	 * @return the {@link BeanMetadataElement} that is the {@link AccessDeniedHandler} to
	 * populate on the {@link CsrfFilter}
	 */
	private BeanMetadataElement createAccessDeniedHandler(BeanDefinition invalidSessionStrategy,
			BeanMetadataElement defaultDeniedHandler) {
		if (invalidSessionStrategy == null) {
			return defaultDeniedHandler;
		}
		ManagedMap<Class<? extends AccessDeniedException>, BeanDefinition> handlers = new ManagedMap<>();
		BeanDefinitionBuilder invalidSessionHandlerBldr = BeanDefinitionBuilder
				.rootBeanDefinition(InvalidSessionAccessDeniedHandler.class);
		invalidSessionHandlerBldr.addConstructorArgValue(invalidSessionStrategy);
		handlers.put(MissingCsrfTokenException.class, invalidSessionHandlerBldr.getBeanDefinition());

		BeanDefinitionBuilder deniedBldr = BeanDefinitionBuilder
				.rootBeanDefinition(DelegatingAccessDeniedHandler.class);
		deniedBldr.addConstructorArgValue(handlers);
		deniedBldr.addConstructorArgValue(defaultDeniedHandler);

		return deniedBldr.getBeanDefinition();
	}

	BeanDefinition getCsrfAuthenticationStrategy() {
		BeanDefinitionBuilder csrfAuthenticationStrategy = BeanDefinitionBuilder
				.rootBeanDefinition(CsrfAuthenticationStrategy.class);
		csrfAuthenticationStrategy.addConstructorArgReference(this.csrfRepositoryRef);
		return csrfAuthenticationStrategy.getBeanDefinition();
	}

	BeanDefinition getCsrfLogoutHandler() {
		BeanDefinitionBuilder csrfAuthenticationStrategy = BeanDefinitionBuilder
				.rootBeanDefinition(CsrfLogoutHandler.class);
		csrfAuthenticationStrategy.addConstructorArgReference(this.csrfRepositoryRef);
		return csrfAuthenticationStrategy.getBeanDefinition();
	}

	void setIgnoreCsrfRequestMatchers(List<BeanDefinition> requestMatchers) {
		if (!requestMatchers.isEmpty()) {
			BeanMetadataElement requestMatcher;
			if (StringUtils.hasText(this.requestMatcherRef)) {
				requestMatcher = new RuntimeBeanReference(this.requestMatcherRef);
			}
			else {
				requestMatcher = new RootBeanDefinition(DefaultRequiresCsrfMatcher.class);
			}
			BeanDefinitionBuilder and = BeanDefinitionBuilder.rootBeanDefinition(AndRequestMatcher.class);
			BeanDefinitionBuilder negated = BeanDefinitionBuilder.rootBeanDefinition(NegatedRequestMatcher.class);
			BeanDefinitionBuilder or = BeanDefinitionBuilder.rootBeanDefinition(OrRequestMatcher.class);
			or.addConstructorArgValue(requestMatchers);
			negated.addConstructorArgValue(or.getBeanDefinition());
			List<BeanMetadataElement> ands = new ManagedList<>();
			ands.add(requestMatcher);
			ands.add(negated.getBeanDefinition());
			and.addConstructorArgValue(ands);
			this.csrfFilter.getPropertyValues().add("requireCsrfProtectionMatcher", and.getBeanDefinition());
		}
	}

	private static final class DefaultRequiresCsrfMatcher implements RequestMatcher {

		private final HashSet<String> allowedMethods = new HashSet<>(Arrays.asList("GET", "HEAD", "TRACE", "OPTIONS"));

		/*
		 * (non-Javadoc)
		 *
		 * @see
		 * org.springframework.security.web.util.matcher.RequestMatcher#matches(javax.
		 * servlet.http.HttpServletRequest)
		 */
		@Override
		public boolean matches(HttpServletRequest request) {
			return !this.allowedMethods.contains(request.getMethod());
		}

	}

}
