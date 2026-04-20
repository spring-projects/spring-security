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

package org.springframework.security.core.context;

import io.micrometer.context.ThreadLocalAccessor;

import org.springframework.util.Assert;

/**
 * A {@link ThreadLocalAccessor} for accessing a {@link SecurityContext} with the
 * {@link SecurityContextHolder}.
 * <p>
 * This class adapts the {@link SecurityContextHolder} to the {@link ThreadLocalAccessor}
 * contract to allow Micrometer Context Propagation to automatically propagate a
 * {@link SecurityContext} in Servlet applications. It is automatically registered with
 * the {@link io.micrometer.context.ContextRegistry} through the
 * {@link java.util.ServiceLoader} mechanism when context-propagation is on the classpath.
 *
 * @author Steve Riesenberg
 * @author Tadaya Tsuyukubo
 * @since 6.5
 * @see io.micrometer.context.ContextRegistry
 */
public final class SecurityContextHolderThreadLocalAccessor implements ThreadLocalAccessor<SecurityContext> {

	@Override
	public Object key() {
		return SecurityContext.class.getName();
	}

	@Override
	public SecurityContext getValue() {
		SecurityContext securityContext = SecurityContextHolder.getContext();
		SecurityContext emptyContext = SecurityContextHolder.createEmptyContext();

		return !securityContext.equals(emptyContext) ? securityContext : null;
	}

	@Override
	public void setValue(SecurityContext securityContext) {
		Assert.notNull(securityContext, "securityContext cannot be null");
		SecurityContext newContext = SecurityContextHolder.createEmptyContext();
		newContext.setAuthentication(securityContext.getAuthentication());
		SecurityContextHolder.setContext(newContext);
	}

	@Override
	public void setValue() {
		SecurityContextHolder.clearContext();
	}

}
