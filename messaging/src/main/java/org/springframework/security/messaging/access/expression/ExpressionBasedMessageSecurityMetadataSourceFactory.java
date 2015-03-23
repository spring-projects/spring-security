/*
 * Copyright 2002-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.messaging.access.expression;

import org.springframework.expression.Expression;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.messaging.access.intercept.DefaultMessageSecurityMetadataSource;
import org.springframework.security.messaging.access.intercept.MessageSecurityMetadataSource;
import org.springframework.security.messaging.util.matcher.MessageMatcher;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * A class used to create a {@link MessageSecurityMetadataSource} that uses
 * {@link MessageMatcher} mapped to Spring Expressions.
 *
 * @since 4.0
 * @author Rob Winch
 */
public final class ExpressionBasedMessageSecurityMetadataSourceFactory {

	/**
	 * Create a {@link MessageSecurityMetadataSource} that uses {@link MessageMatcher}
	 * mapped to Spring Expressions. Each entry is considered in order and only the first
	 * match is used.
	 *
	 * For example:
	 *
	 * <pre>
	 *     LinkedHashMap<MessageMatcher<?> matcherToExpression = new LinkedHashMap<MessageMatcher<Object>();
	 *     matcherToExpression.put(new SimDestinationMessageMatcher("/public/**"), "permitAll");
	 *     matcherToExpression.put(new SimDestinationMessageMatcher("/admin/**"), "hasRole('ROLE_ADMIN')");
	 *     matcherToExpression.put(new SimDestinationMessageMatcher("/**"), "authenticated");
	 * 
	 *     MessageSecurityMetadataSource metadataSource = createExpressionMessageMetadataSource(matcherToExpression);
	 * </pre>
	 *
	 * <p>
	 * If our destination is "/public/hello", it would match on "/public/**" and on "/**".
	 * However, only "/public/**" would be used since it is the first entry. That means
	 * that a destination of "/public/hello" will be mapped to "permitAll".
	 * </p>
	 *
	 * <p>
	 * For a complete listing of expressions see {@link MessageSecurityExpressionRoot}
	 * </p>
	 *
	 * @param matcherToExpression an ordered mapping of {@link MessageMatcher} to Strings
	 * that are turned into an Expression using
	 * {@link DefaultMessageSecurityExpressionHandler#getExpressionParser()}
	 * @return the {@link MessageSecurityMetadataSource} to use. Cannot be null.
	 */
	public static MessageSecurityMetadataSource createExpressionMessageMetadataSource(
			LinkedHashMap<MessageMatcher<?>, String> matcherToExpression) {
		DefaultMessageSecurityExpressionHandler<Object> handler = new DefaultMessageSecurityExpressionHandler<Object>();

		LinkedHashMap<MessageMatcher<?>, Collection<ConfigAttribute>> matcherToAttrs = new LinkedHashMap<MessageMatcher<?>, Collection<ConfigAttribute>>();

		for (Map.Entry<MessageMatcher<?>, String> entry : matcherToExpression.entrySet()) {
			MessageMatcher<?> matcher = entry.getKey();
			String rawExpression = entry.getValue();
			Expression expression = handler.getExpressionParser().parseExpression(
					rawExpression);
			ConfigAttribute attribute = new MessageExpressionConfigAttribute(expression);
			matcherToAttrs.put(matcher, Arrays.asList(attribute));
		}
		return new DefaultMessageSecurityMetadataSource(matcherToAttrs);
	}

	private ExpressionBasedMessageSecurityMetadataSourceFactory() {
	}
}