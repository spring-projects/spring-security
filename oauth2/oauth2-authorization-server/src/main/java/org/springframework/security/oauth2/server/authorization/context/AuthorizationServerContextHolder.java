/*
 * Copyright 2020-2022 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.context;

/**
 * A holder of the {@link AuthorizationServerContext} that associates it with the current
 * thread using a {@code ThreadLocal}.
 *
 * @author Joe Grandja
 * @since 0.2.2
 * @see AuthorizationServerContext
 */
public final class AuthorizationServerContextHolder {

	private static final ThreadLocal<AuthorizationServerContext> holder = new ThreadLocal<>();

	private AuthorizationServerContextHolder() {
	}

	/**
	 * Returns the {@link AuthorizationServerContext} bound to the current thread.
	 * @return the {@link AuthorizationServerContext}
	 */
	public static AuthorizationServerContext getContext() {
		return holder.get();
	}

	/**
	 * Bind the given {@link AuthorizationServerContext} to the current thread.
	 * @param authorizationServerContext the {@link AuthorizationServerContext}
	 */
	public static void setContext(AuthorizationServerContext authorizationServerContext) {
		if (authorizationServerContext == null) {
			resetContext();
		}
		else {
			holder.set(authorizationServerContext);
		}
	}

	/**
	 * Reset the {@link AuthorizationServerContext} bound to the current thread.
	 */
	public static void resetContext() {
		holder.remove();
	}

}
