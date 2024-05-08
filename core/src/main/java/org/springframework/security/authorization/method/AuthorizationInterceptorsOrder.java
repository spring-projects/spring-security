/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.authorization.method;

import org.springframework.aop.Advisor;

/**
 * Ordering of Spring Security's authorization {@link Advisor}s
 *
 * @author Josh Cummings
 * @since 5.6
 * @see PreAuthorizeAuthorizationManager
 * @see PostAuthorizeAuthorizationManager
 * @see SecuredAuthorizationManager
 * @see Jsr250AuthorizationManager
 */
public enum AuthorizationInterceptorsOrder {

	FIRST(Integer.MIN_VALUE),

	/**
	 * {@link PreFilterAuthorizationMethodInterceptor}
	 */
	PRE_FILTER,

	PRE_AUTHORIZE,

	SECURED,

	JSR250,

	POST_AUTHORIZE,

	/**
	 * {@link PostFilterAuthorizationMethodInterceptor}
	 */
	POST_FILTER,

	LAST(Integer.MAX_VALUE);

	private static final int INTERVAL = 100;

	private final int order;

	AuthorizationInterceptorsOrder() {
		this.order = ordinal() * INTERVAL;
	}

	AuthorizationInterceptorsOrder(int order) {
		this.order = order;
	}

	public int getOrder() {
		return this.order;
	}

}
