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
import org.springframework.expression.ParseException;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.util.Assert;

/**
 * Contains both filtering and authorization expression meta-data for Spring-EL based
 * access control.
 * <p>
 * Base class for pre or post-invocation phases of a method invocation.
 * <p>
 * Either filter or authorization expressions may be null, but not both.
 *
 * @author Luke Taylor
 * @since 3.0
 */
abstract class AbstractExpressionBasedMethodConfigAttribute implements ConfigAttribute {

	private final Expression filterExpression;

	private final Expression authorizeExpression;

	/**
	 * Parses the supplied expressions as Spring-EL.
	 */
	AbstractExpressionBasedMethodConfigAttribute(String filterExpression, String authorizeExpression)
			throws ParseException {
		Assert.isTrue(filterExpression != null || authorizeExpression != null,
				"Filter and authorization Expressions cannot both be null");
		SpelExpressionParser parser = new SpelExpressionParser();
		this.filterExpression = filterExpression == null ? null : parser.parseExpression(filterExpression);
		this.authorizeExpression = authorizeExpression == null ? null : parser.parseExpression(authorizeExpression);
	}

	AbstractExpressionBasedMethodConfigAttribute(Expression filterExpression, Expression authorizeExpression)
			throws ParseException {
		Assert.isTrue(filterExpression != null || authorizeExpression != null,
				"Filter and authorization Expressions cannot both be null");
		this.filterExpression = filterExpression == null ? null : filterExpression;
		this.authorizeExpression = authorizeExpression == null ? null : authorizeExpression;
	}

	Expression getFilterExpression() {
		return this.filterExpression;
	}

	Expression getAuthorizeExpression() {
		return this.authorizeExpression;
	}

	@Override
	public String getAttribute() {
		return null;
	}

}
