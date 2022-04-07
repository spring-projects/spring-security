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

package org.springframework.security.messaging.access.expression;

import java.util.Arrays;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.expression.Expression;
import org.springframework.messaging.Message;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.messaging.access.intercept.DefaultMessageSecurityMetadataSource;
import org.springframework.security.messaging.access.intercept.MessageSecurityMetadataSource;
import org.springframework.security.messaging.util.matcher.MessageMatcher;

/**
 * A class used to create a {@link MessageSecurityMetadataSource} that uses
 * {@link MessageMatcher} mapped to Spring Expressions.
 *
 * @author Rob Winch
 * @since 4.0
 */
public final class ExpressionBasedMessageSecurityMetadataSourceFactory {

	private ExpressionBasedMessageSecurityMetadataSourceFactory() {
	}

	/**
	 * Create a {@link MessageSecurityMetadataSource} that uses {@link MessageMatcher}
	 * mapped to Spring Expressions. Each entry is considered in order and only the first
	 * match is used.
	 *
	 * For example:
	 *
	 * <pre>
	 *     LinkedHashMap&lt;MessageMatcher&lt;?&gt;,String&gt; matcherToExpression = new LinkedHashMap&lt;MessageMatcher&lt;Object&gt;,String&gt;();
	 *     matcherToExpression.put(new SimDestinationMessageMatcher("/public/**"), "permitAll");
	 *     matcherToExpression.put(new SimDestinationMessageMatcher("/admin/**"), "hasRole('ROLE_ADMIN')");
	 *     matcherToExpression.put(new SimDestinationMessageMatcher("/topics/{name}/**"), "@someBean.customLogic(authentication, #name)");
	 *     matcherToExpression.put(new SimDestinationMessageMatcher("/**"), "authenticated");
	 *
	 *     MessageSecurityMetadataSource metadataSource = createExpressionMessageMetadataSource(matcherToExpression);
	 * </pre>
	 *
	 * <p>
	 * If our destination is "/public/hello", it would match on "/public/**" and on "/**".
	 * However, only "/public/**" would be used since it is the first entry. That means
	 * that a destination of "/public/hello" will be mapped to "permitAll".
	 *
	 * <p>
	 * For a complete listing of expressions see {@link MessageSecurityExpressionRoot}
	 * @param matcherToExpression an ordered mapping of {@link MessageMatcher} to Strings
	 * that are turned into an Expression using
	 * {@link DefaultMessageSecurityExpressionHandler#getExpressionParser()}
	 * @return the {@link MessageSecurityMetadataSource} to use. Cannot be null.
	 */
	public static MessageSecurityMetadataSource createExpressionMessageMetadataSource(
			LinkedHashMap<MessageMatcher<?>, String> matcherToExpression) {
		return createExpressionMessageMetadataSource(matcherToExpression,
				new DefaultMessageSecurityExpressionHandler<>());
	}

	/**
	 * Create a {@link MessageSecurityMetadataSource} that uses {@link MessageMatcher}
	 * mapped to Spring Expressions. Each entry is considered in order and only the first
	 * match is used.
	 *
	 * For example:
	 *
	 * <pre>
	 *     LinkedHashMap&lt;MessageMatcher&lt;?&gt;,String&gt; matcherToExpression = new LinkedHashMap&lt;MessageMatcher&lt;Object&gt;,String&gt;();
	 *     matcherToExpression.put(new SimDestinationMessageMatcher("/public/**"), "permitAll");
	 *     matcherToExpression.put(new SimDestinationMessageMatcher("/admin/**"), "hasRole('ROLE_ADMIN')");
	 *     matcherToExpression.put(new SimDestinationMessageMatcher("/topics/{name}/**"), "@someBean.customLogic(authentication, #name)");
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
	 * @param matcherToExpression an ordered mapping of {@link MessageMatcher} to Strings
	 * that are turned into an Expression using
	 * {@link DefaultMessageSecurityExpressionHandler#getExpressionParser()}
	 * @param handler the {@link SecurityExpressionHandler} to use
	 * @return the {@link MessageSecurityMetadataSource} to use. Cannot be null.
	 */
	public static MessageSecurityMetadataSource createExpressionMessageMetadataSource(
			LinkedHashMap<MessageMatcher<?>, String> matcherToExpression,
			SecurityExpressionHandler<Message<Object>> handler) {
		LinkedHashMap<MessageMatcher<?>, Collection<ConfigAttribute>> matcherToAttrs = new LinkedHashMap<>();
		for (Map.Entry<MessageMatcher<?>, String> entry : matcherToExpression.entrySet()) {
			MessageMatcher<?> matcher = entry.getKey();
			String rawExpression = entry.getValue();
			Expression expression = handler.getExpressionParser().parseExpression(rawExpression);
			ConfigAttribute attribute = new MessageExpressionConfigAttribute(expression, matcher);
			matcherToAttrs.put(matcher, Arrays.asList(attribute));
		}
		return new DefaultMessageSecurityMetadataSource(matcherToAttrs);
	}

}
