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

package org.springframework.security.access.expression.method;

import org.springframework.expression.Expression;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.ParseException;
import org.springframework.security.access.prepost.PostInvocationAttribute;
import org.springframework.security.access.prepost.PreInvocationAttribute;
import org.springframework.security.access.prepost.PrePostInvocationAttributeFactory;

/**
 * {@link PrePostInvocationAttributeFactory} which interprets the annotation value as an
 * expression to be evaluated at runtime.
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.0
 * @deprecated Use {@link org.springframework.security.authorization.AuthorizationManager}
 * interceptors instead
 */
@Deprecated
public class ExpressionBasedAnnotationAttributeFactory implements PrePostInvocationAttributeFactory {

	private final Object parserLock = new Object();

	private ExpressionParser parser;

	private MethodSecurityExpressionHandler handler;

	public ExpressionBasedAnnotationAttributeFactory(MethodSecurityExpressionHandler handler) {
		this.handler = handler;
	}

	@Override
	public PreInvocationAttribute createPreInvocationAttribute(String preFilterAttribute, String filterObject,
			String preAuthorizeAttribute) {
		try {
			// TODO: Optimization of permitAll
			ExpressionParser parser = getParser();
			Expression preAuthorizeExpression = (preAuthorizeAttribute != null)
					? parser.parseExpression(preAuthorizeAttribute) : parser.parseExpression("permitAll");
			Expression preFilterExpression = (preFilterAttribute != null) ? parser.parseExpression(preFilterAttribute)
					: null;
			return new PreInvocationExpressionAttribute(preFilterExpression, filterObject, preAuthorizeExpression);
		}
		catch (ParseException ex) {
			throw new IllegalArgumentException("Failed to parse expression '" + ex.getExpressionString() + "'", ex);
		}
	}

	@Override
	public PostInvocationAttribute createPostInvocationAttribute(String postFilterAttribute,
			String postAuthorizeAttribute) {
		try {
			ExpressionParser parser = getParser();
			Expression postAuthorizeExpression = (postAuthorizeAttribute != null)
					? parser.parseExpression(postAuthorizeAttribute) : null;
			Expression postFilterExpression = (postFilterAttribute != null)
					? parser.parseExpression(postFilterAttribute) : null;
			if (postFilterExpression != null || postAuthorizeExpression != null) {
				return new PostInvocationExpressionAttribute(postFilterExpression, postAuthorizeExpression);
			}
		}
		catch (ParseException ex) {
			throw new IllegalArgumentException("Failed to parse expression '" + ex.getExpressionString() + "'", ex);
		}

		return null;
	}

	/**
	 * Delay the lookup of the {@link ExpressionParser} to prevent SEC-2136
	 * @return
	 */
	private ExpressionParser getParser() {
		if (this.parser != null) {
			return this.parser;
		}
		synchronized (this.parserLock) {
			this.parser = this.handler.getExpressionParser();
			this.handler = null;
		}
		return this.parser;
	}

}
