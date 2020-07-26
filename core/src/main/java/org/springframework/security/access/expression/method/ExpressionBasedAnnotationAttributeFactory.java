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
 */
public class ExpressionBasedAnnotationAttributeFactory implements PrePostInvocationAttributeFactory {

	private final Object parserLock = new Object();

	private ExpressionParser parser;

	private MethodSecurityExpressionHandler handler;

	public ExpressionBasedAnnotationAttributeFactory(MethodSecurityExpressionHandler handler) {
		this.handler = handler;
	}

	public PreInvocationAttribute createPreInvocationAttribute(String preFilterAttribute, String filterObject,
			String preAuthorizeAttribute) {
		try {
			// TODO: Optimization of permitAll
			ExpressionParser parser = getParser();
			Expression preAuthorizeExpression = preAuthorizeAttribute == null ? parser.parseExpression("permitAll")
					: parser.parseExpression(preAuthorizeAttribute);
			Expression preFilterExpression = preFilterAttribute == null ? null
					: parser.parseExpression(preFilterAttribute);
			return new PreInvocationExpressionAttribute(preFilterExpression, filterObject, preAuthorizeExpression);
		}
		catch (ParseException e) {
			throw new IllegalArgumentException("Failed to parse expression '" + e.getExpressionString() + "'", e);
		}
	}

	public PostInvocationAttribute createPostInvocationAttribute(String postFilterAttribute,
			String postAuthorizeAttribute) {
		try {
			ExpressionParser parser = getParser();
			Expression postAuthorizeExpression = postAuthorizeAttribute == null ? null
					: parser.parseExpression(postAuthorizeAttribute);
			Expression postFilterExpression = postFilterAttribute == null ? null
					: parser.parseExpression(postFilterAttribute);

			if (postFilterExpression != null || postAuthorizeExpression != null) {
				return new PostInvocationExpressionAttribute(postFilterExpression, postAuthorizeExpression);
			}
		}
		catch (ParseException e) {
			throw new IllegalArgumentException("Failed to parse expression '" + e.getExpressionString() + "'", e);
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
