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

package org.springframework.security.messaging.access.expression;

import java.util.function.Supplier;

import org.springframework.messaging.Message;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.core.Authentication;

/**
 * The {@link SecurityExpressionRoot} used for {@link Message} expressions.
 *
 * @author Rob Winch
 * @author Evgeniy Cheban
 * @since 4.0
 */
public class MessageSecurityExpressionRoot extends SecurityExpressionRoot {

	public final Message<?> message;

	public MessageSecurityExpressionRoot(Authentication authentication, Message<?> message) {
		this(() -> authentication, message);
	}

	/**
	 * Creates an instance for the given {@link Supplier} of the {@link Authentication}
	 * and {@link Message}.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to use
	 * @param message the {@link Message} to use
	 * @since 5.8
	 */
	public MessageSecurityExpressionRoot(Supplier<Authentication> authentication, Message<?> message) {
		super(authentication);
		this.message = message;
	}

}
