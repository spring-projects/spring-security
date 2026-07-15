/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

import org.jspecify.annotations.Nullable;

import org.springframework.util.Assert;

/**
 * A <code>ThreadLocal</code>-based implementation of
 * {@link SecurityContextHolderStrategy}.
 *
 * @author Ben Alex
 * @author Rob Winch
 * @see java.lang.ThreadLocal
 * @see org.springframework.security.core.context.web.SecurityContextPersistenceFilter
 */
final class ThreadLocalSecurityContextHolderStrategy implements SecurityContextHolderStrategy {

	private static final ThreadLocal<Supplier<SecurityContext>> contextHolder = new ThreadLocal<>();

	@Override
	public void clearContext() {
		contextHolder.remove();
	}

	@Override
	public SecurityContext getContext() {
		return getDeferredContext().get();
	}

	@Override
	public Supplier<SecurityContext> getDeferredContext() {
		Supplier<SecurityContext> result = contextHolder.get();
		if (result == null) {
			result = new ConstantSupplier(createEmptyContext());
			contextHolder.set(result);
		}
		return result;
	}

	@Override
	public void setContext(SecurityContext context) {
		Assert.notNull(context, "Only non-null SecurityContext instances are permitted");
		contextHolder.set(new ConstantSupplier(context));
	}

	@Override
	public void setDeferredContext(Supplier<SecurityContext> deferredContext) {
		Assert.notNull(deferredContext, "Only non-null Supplier instances are permitted");
		Supplier<SecurityContext> notNullDeferredContext = (deferredContext instanceof NotNullSupplier
				|| deferredContext instanceof ConstantSupplier) ? deferredContext
						: new NotNullSupplier(deferredContext);
		contextHolder.set(notNullDeferredContext);
	}

	@Override
	public SecurityContext createEmptyContext() {
		return new SecurityContextImpl();
	}

	@Override
	public @Nullable Supplier<SecurityContext> peekDeferredContext() {
		return contextHolder.get();
	}

}
