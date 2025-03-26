/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.web.access.expression;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.function.BiConsumer;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.ParseException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.annotation.SecurityAnnotationScanner;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Expression-based {@code FilterInvocationSecurityMetadataSource}.
 *
 * @author Luke Taylor
 * @author Eddú Meléndez
 * @since 3.0
 * @deprecated In modern Spring Security APIs, each API manages its own configuration
 * context. As such there is no direct replacement for this interface. In the case of
 * method security, please see {@link SecurityAnnotationScanner} and
 * {@link AuthorizationManager}. In the case of channel security, please see
 * {@code HttpsRedirectFilter}. In the case of web security, please see
 * {@link AuthorizationManager}.
 */
@Deprecated
public final class ExpressionBasedFilterInvocationSecurityMetadataSource
		extends DefaultFilterInvocationSecurityMetadataSource {

	private static final Log logger = LogFactory.getLog(ExpressionBasedFilterInvocationSecurityMetadataSource.class);

	public ExpressionBasedFilterInvocationSecurityMetadataSource(
			LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap,
			SecurityExpressionHandler<FilterInvocation> expressionHandler) {
		super(processMap(requestMap, expressionHandler.getExpressionParser()));
		Assert.notNull(expressionHandler, "A non-null SecurityExpressionHandler is required");
	}

	private static LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> processMap(
			LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestMap, ExpressionParser parser) {
		Assert.notNull(parser, "SecurityExpressionHandler returned a null parser object");
		LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> processed = new LinkedHashMap<>(requestMap);
		requestMap.forEach((request, value) -> process(parser, request, value, processed::put));
		return processed;
	}

	private static void process(ExpressionParser parser, RequestMatcher request, Collection<ConfigAttribute> value,
			BiConsumer<RequestMatcher, Collection<ConfigAttribute>> consumer) {
		String expression = getExpression(request, value);
		if (logger.isDebugEnabled()) {
			logger.debug(LogMessage.format("Adding web access control expression [%s] for %s", expression, request));
		}
		AbstractVariableEvaluationContextPostProcessor postProcessor = createPostProcessor(request);
		ArrayList<ConfigAttribute> processed = new ArrayList<>(1);
		try {
			processed.add(new WebExpressionConfigAttribute(parser.parseExpression(expression), postProcessor));
		}
		catch (ParseException ex) {
			throw new IllegalArgumentException("Failed to parse expression '" + expression + "'");
		}
		consumer.accept(request, processed);
	}

	private static String getExpression(RequestMatcher request, Collection<ConfigAttribute> value) {
		Assert.isTrue(value.size() == 1, () -> "Expected a single expression attribute for " + request);
		return value.toArray(new ConfigAttribute[1])[0].getAttribute();
	}

	private static AbstractVariableEvaluationContextPostProcessor createPostProcessor(RequestMatcher request) {
		return new RequestVariablesExtractorEvaluationContextPostProcessor(request);
	}

	static class RequestVariablesExtractorEvaluationContextPostProcessor
			extends AbstractVariableEvaluationContextPostProcessor {

		private final RequestMatcher matcher;

		RequestVariablesExtractorEvaluationContextPostProcessor(RequestMatcher matcher) {
			this.matcher = matcher;
		}

		@Override
		Map<String, String> extractVariables(HttpServletRequest request) {
			return this.matcher.matcher(request).getVariables();
		}

	}

}
