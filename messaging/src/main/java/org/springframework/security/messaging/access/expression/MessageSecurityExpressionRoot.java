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

import org.springframework.messaging.Message;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.core.Authentication;

/**
 * The {@link SecurityExpressionRoot} used for {@link Message} expressions.
 *
 * @author Rob Winch
 * @author Evgeniy Cheban
 * @author Steve Riesenberg
 * @since 4.0
 */
public class MessageSecurityExpressionRoot<T> extends SecurityExpressionRoot<Message<T>> {

	public final Message<T> message;

	public MessageSecurityExpressionRoot(Authentication authentication, Message<T> message) {
		this(() -> authentication, message);
	}

	/**
	 * Creates an instance for the given {@link Supplier} of the {@link Authentication}
	 * and {@link Message}.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to use
	 * @param message the {@link Message} to use
	 * @since 5.8
	 */
	public MessageSecurityExpressionRoot(Supplier<? extends @Nullable Authentication> authentication,
			Message<T> message) {
		super(authentication, message);
		this.message = message;
	}

}
