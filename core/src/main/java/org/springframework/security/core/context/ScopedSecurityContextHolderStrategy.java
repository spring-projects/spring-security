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
 * A <code>ScopedValue</code>-based implementation of
 * {@link SecurityContextHolderStrategy}.
 *
 * <p>
 * </p>
 * Unlike {@link ThreadLocalSecurityContextHolderStrategy}, for example, this
 * implementation cannot be used "out-of-the-box". Instead, {@link #SECURITY_CONTEXT}
 * <code>ScopedValue</code> has to be bound to
 * {@link ScopedSecurityContextHolderStrategy.SecurityContextScopedValueHolder
 * SecurityContextScopedValueHolder} instance for the current thread. This could be
 * achieved by invoking static {@link #runWhere(Supplier, Runnable)} or
 * {@link #getSecuriyContextCarrier()} methods anywhere down-stack of the code which
 * invokes any of the {@link SecurityContextHolderStrategy} methods, for example in a
 * Spring Security Filter.
 *
 * <p>
 * </p>
 * See
 * <code>org.springframework.security.web.context.ScopedSecurityContextHolderFilter</code>.
 *
 * @see ScopedValue
 */
public class ScopedSecurityContextHolderStrategy implements SecurityContextHolderStrategy {

	/**
	 * An instance of {@link ScopedValue} which has to be bound to an instance of
	 * {@link SecurityContextScopedValueHolder}.
	 */
	private static final ScopedValue<SecurityContextScopedValueHolder> SECURITY_CONTEXT = ScopedValue.newInstance();

	@Override
	public void clearContext() {
		if (SECURITY_CONTEXT.isBound()) {
			retrieveSecurityContextScopedValueHolder().setSecurityContext(null);
		}
		// no action is needed if SECURITY_CONTEXT ScopedValue is not bound for the
		// current thread.
	}

	@Override
	public SecurityContext getContext() {
		return getDeferredContext().get();
	}

	@Override
	public Supplier<SecurityContext> getDeferredContext() {
		final SecurityContextScopedValueHolder holder = retrieveSecurityContextScopedValueHolder();
		@Nullable Supplier<SecurityContext> result = holder.getSecurityContext();
		if (result == null) {
			SecurityContext context = createEmptyContext();
			result = () -> context;
			holder.setSecurityContext(result);
		}
		return result;
	}

	@Override
	public void setContext(SecurityContext context) {
		Assert.notNull(context, "Only non-null SecurityContext instances are permitted");
		retrieveSecurityContextScopedValueHolder().setSecurityContext(() -> context);
	}

	@Override
	public SecurityContext createEmptyContext() {
		return new SecurityContextImpl();
	}

	private SecurityContextScopedValueHolder retrieveSecurityContextScopedValueHolder() {
		if (SECURITY_CONTEXT.isBound()) {
			return SECURITY_CONTEXT.get();
		}
		else {
			throw new IllegalStateException("Security Context Scoped Value not bound");
		}
	}

	@Override
	public void setDeferredContext(Supplier<SecurityContext> deferredContext) {
		Assert.notNull(deferredContext, "Only non-null Supplier instances are permitted");
		Supplier<SecurityContext> notNullDeferredContext = () -> {
			SecurityContext result = deferredContext.get();
			Assert.notNull(result, "A Supplier<SecurityContext> returned null and is not allowed.");
			return result;
		};
		retrieveSecurityContextScopedValueHolder().setSecurityContext(notNullDeferredContext);
	}

	/**
	 * Binds an instance of {@link ScopedValue},
	 * {@link ScopedSecurityContextHolderStrategy#SECURITY_CONTEXT}, to an instance of
	 * {@link SecurityContextScopedValueHolder} <i>for current thread</i>.
	 */
	public static void runWhere(Supplier<SecurityContext> deferredContext, Runnable r) {
		ScopedValue.where(SECURITY_CONTEXT, new SecurityContextScopedValueHolder(deferredContext)).run(r);
	}

	/**
	 * A convenience version of {@link #runWhere(Supplier, Runnable)} method.
	 */
	public static ScopedValue.Carrier getSecuriyContextCarrier() {
		return ScopedValue.where(SECURITY_CONTEXT, new SecurityContextScopedValueHolder());
	}

	/**
	 * A structure that holds {@link SecurityContext}. An instance of {@link ScopedValue},
	 * {@link ScopedSecurityContextHolderStrategy#SECURITY_CONTEXT}, has to be bound to an
	 * instance of this class.
	 */
	private static class SecurityContextScopedValueHolder {

		@Nullable private Supplier<SecurityContext> securityContext;

		SecurityContextScopedValueHolder() {
		}

		SecurityContextScopedValueHolder(Supplier<SecurityContext> securityContext) {
			this.securityContext = securityContext;
		}

		@Nullable Supplier<SecurityContext> getSecurityContext() {
			return this.securityContext;
		}

		void setSecurityContext(@Nullable Supplier<SecurityContext> securityContext) {
			this.securityContext = securityContext;
		}

	}

}
