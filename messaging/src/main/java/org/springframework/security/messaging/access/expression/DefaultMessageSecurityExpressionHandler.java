/*
 * Copyright 2004-present the original author or authors.
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

import java.util.function.Supplier;

import org.jspecify.annotations.Nullable;

import org.springframework.expression.BeanResolver;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.spel.support.StandardEvaluationContext;
import org.springframework.messaging.Message;
import org.springframework.security.access.expression.AbstractSecurityExpressionHandler;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.core.Authentication;

/**
 * The default implementation of {@link SecurityExpressionHandler} which uses a
 * {@link MessageSecurityExpressionRoot}.
 *
 * @param <T> the type for the body of the Message
 * @author Rob Winch
 * @author Evgeniy Cheban
 * @since 4.0
 */
public class DefaultMessageSecurityExpressionHandler<T> extends AbstractSecurityExpressionHandler<Message<T>> {

	@Override
	public EvaluationContext createEvaluationContext(Supplier<? extends @Nullable Authentication> authentication,
			Message<T> message) {
		MessageSecurityExpressionRoot<T> root = createSecurityExpressionRoot(authentication, message);
		StandardEvaluationContext ctx = new StandardEvaluationContext(root);
		BeanResolver beanResolver = getBeanResolver();
		if (beanResolver != null) {
			// https://github.com/spring-projects/spring-framework/issues/35371
			ctx.setBeanResolver(beanResolver);
		}
		return ctx;
	}

	@Override
	protected SecurityExpressionOperations createSecurityExpressionRoot(@Nullable Authentication authentication,
			Message<T> invocation) {
		return createSecurityExpressionRoot(() -> authentication, invocation);
	}

	private MessageSecurityExpressionRoot<T> createSecurityExpressionRoot(
			Supplier<? extends Authentication> authentication, Message<T> invocation) {
		MessageSecurityExpressionRoot<T> root = new MessageSecurityExpressionRoot<>(authentication, invocation);
		root.setAuthorizationManagerFactory(getAuthorizationManagerFactory());
		root.setPermissionEvaluator(getPermissionEvaluator());
		return root;
	}

	/**
	 * @deprecated Use
	 * {@link #setAuthorizationManagerFactory(AuthorizationManagerFactory)} instead
	 */
	@Deprecated(since = "7.0")
	public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
		getDefaultAuthorizationManagerFactory().setTrustResolver(trustResolver);
	}

}
