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

package org.springframework.security.web.access.expression;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.expression.ExpressionParser;
import org.springframework.expression.ParseException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.DefaultFilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Expression-based {@code FilterInvocationSecurityMetadataSource}.
 *
 * @author Luke Taylor
 * @author Eddú Meléndez
 * @since 3.0
 */
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

		LinkedHashMap<RequestMatcher, Collection<ConfigAttribute>> requestToExpressionAttributesMap = new LinkedHashMap<>(
				requestMap);

		for (Map.Entry<RequestMatcher, Collection<ConfigAttribute>> entry : requestMap.entrySet()) {
			RequestMatcher request = entry.getKey();
			Assert.isTrue(entry.getValue().size() == 1, () -> "Expected a single expression attribute for " + request);
			ArrayList<ConfigAttribute> attributes = new ArrayList<>(1);
			String expression = entry.getValue().toArray(new ConfigAttribute[1])[0].getAttribute();
			logger.debug("Adding web access control expression '" + expression + "', for " + request);

			AbstractVariableEvaluationContextPostProcessor postProcessor = createPostProcessor(request);
			try {
				attributes.add(new WebExpressionConfigAttribute(parser.parseExpression(expression), postProcessor));
			}
			catch (ParseException ex) {
				throw new IllegalArgumentException("Failed to parse expression '" + expression + "'");
			}

			requestToExpressionAttributesMap.put(request, attributes);
		}

		return requestToExpressionAttributesMap;
	}

	private static AbstractVariableEvaluationContextPostProcessor createPostProcessor(RequestMatcher request) {
		return new RequestVariablesExtractorEvaluationContextPostProcessor(request);
	}

	static class AntPathMatcherEvaluationContextPostProcessor extends AbstractVariableEvaluationContextPostProcessor {

		private final AntPathRequestMatcher matcher;

		AntPathMatcherEvaluationContextPostProcessor(AntPathRequestMatcher matcher) {
			this.matcher = matcher;
		}

		@Override
		Map<String, String> extractVariables(HttpServletRequest request) {
			return this.matcher.matcher(request).getVariables();
		}

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
