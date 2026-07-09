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

import java.util.function.Supplier;

import io.micrometer.context.ThreadLocalAccessor;
import org.jspecify.annotations.Nullable;

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
 * <p>
 * The propagated value is the deferred {@link Supplier}, so capture does not materialize
 * the {@link SecurityContext}; the supplier is invoked lazily on the consuming thread. An
 * already-materialized {@link SecurityContext} that equals the empty context is treated
 * as absent and is not propagated.
 *
 * @author Steve Riesenberg
 * @since 6.5
 * @see io.micrometer.context.ContextRegistry
 */
public final class SecurityContextHolderThreadLocalAccessor implements ThreadLocalAccessor<Supplier<SecurityContext>> {

	@Override
	public Object key() {
		return SecurityContext.class.getName();
	}

	@Override
	public @Nullable Supplier<SecurityContext> getValue() {
		Supplier<SecurityContext> deferred = SecurityContextHolder.getContextHolderStrategy().peekDeferredContext();
		// The empty check is only possible when the context is already materialized;
		// invoking a deferred supplier here would reintroduce gh-18059.
		if (deferred instanceof ConstantSupplier constant
				&& constant.get().equals(SecurityContextHolder.createEmptyContext())) {
			return null;
		}
		return deferred;
	}

	@Override
	public void setValue(Supplier<SecurityContext> securityContext) {
		Assert.notNull(securityContext, "securityContext cannot be null");
		SecurityContextHolder.getContextHolderStrategy().setDeferredContext(securityContext);
	}

	@Override
	public void setValue() {
		SecurityContextHolder.clearContext();
	}

}
