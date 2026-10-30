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

import java.util.concurrent.Callable;
import java.util.function.Supplier;

import org.jspecify.annotations.Nullable;

import org.springframework.core.task.TaskDecorator;
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
		if (isBound()) {
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
	 * @return <code>true</code> if an nstance of {@link ScopedValue},
	 * {@link ScopedSecurityContextHolderStrategy#SECURITY_CONTEXT} is bound to the
	 * current thread; otherwise <code>false</code>.
	 */
	public boolean isBound() {
		return SECURITY_CONTEXT.isBound();
	}

	/**
	 * @return {@link TaskDecorator} binds an instance of {@link ScopedValue},
	 * {@link ScopedSecurityContextHolderStrategy#SECURITY_CONTEXT} for a thread which
	 * invokes {@link TaskDecorator#decorate(Runnable)}.
	 */
	public static TaskDecorator getTaskDecorator() {
		return (runnable) -> () -> getSecuriyContextCarrier().run(runnable);
	}

	/**
	 * Binds an instance of {@link ScopedValue},
	 * {@link ScopedSecurityContextHolderStrategy#SECURITY_CONTEXT}, to an instance of
	 * {@link SecurityContextScopedValueHolder} <i>for current thread</i> and runs
	 * <code>runnable</code> argument.
	 */
	public static void runWhere(Supplier<SecurityContext> deferredContext, Runnable runnable) {
		ScopedValue.where(SECURITY_CONTEXT, new SecurityContextScopedValueHolder(deferredContext)).run(runnable);
	}

	/**
	 * A version of {@link #runWhere(Supplier, Runnable)} method used in a case when
	 * {@link SecurityContext} is not available.
	 */
	public static ScopedValue.Carrier getSecuriyContextCarrier() {
		return ScopedValue.where(SECURITY_CONTEXT, new SecurityContextScopedValueHolder());
	}

	/**
	 * Binds an instance of {@link ScopedValue},
	 * {@link ScopedSecurityContextHolderStrategy#SECURITY_CONTEXT}, to an instance of
	 * {@link SecurityContextScopedValueHolder} <i>for current thread</i> and calls
	 * <code>callableOp</code> argument.
	 *
	 * <p>
	 * </p>
	 * See also {@link DelegatingSecurityContextRunnable}.
	 */
	public static <R, X extends Throwable> R callWhere(Supplier<SecurityContext> deferredContext,
			ScopedValue.CallableOp<? extends R, X> callableOp) throws X {
		return ScopedValue.where(SECURITY_CONTEXT, new SecurityContextScopedValueHolder(deferredContext))
			.call(callableOp);
	}

	/**
	 * Binds an instance of {@link ScopedValue},
	 * {@link ScopedSecurityContextHolderStrategy#SECURITY_CONTEXT}, to an instance of
	 * {@link SecurityContextScopedValueHolder} <i>for current thread</i> and calls
	 * <code>callable</code> argument.
	 *
	 * <p>
	 * </p>
	 * See also {@link DelegatingSecurityContextCallable}.
	 */
	public static <R> R callWhere(Supplier<SecurityContext> deferredContext, Callable<? extends R> callable)
			throws Exception {
		return ScopedValue.where(SECURITY_CONTEXT, new SecurityContextScopedValueHolder(deferredContext))
			.call(new CallableOpOfCallable<R>(callable));
	}

	/**
	 * A converter from {@link ScopedValue.CallableOp} to {@link Callable}.
	 *
	 * @param <T> the result type of method call.
	 */
	private static class CallableOpOfCallable<T> implements ScopedValue.CallableOp<T, Exception> {

		private final Callable<? extends T> callable;

		CallableOpOfCallable(Callable<? extends T> op) {
			this.callable = op;
		}

		@Override
		public T call() throws Exception {
			return this.callable.call();
		}

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

	/**
	 * A ScopedSecurityContextHolderStrategy-specific version of
	 * {@link org.springframework.security.concurrent.DelegatingSecurityContextCallable
	 * DelegatingSecurityContextCallable}.
	 *
	 * @param <R> the result type of {@link Callable#call()} method
	 */
	public static class DelegatingSecurityContextCallable<R> implements Callable<R> {

		private final @Nullable SecurityContext securityContext;

		private final Callable<R> delegate;

		private final ScopedSecurityContextHolderStrategy strategy = new ScopedSecurityContextHolderStrategy();

		public DelegatingSecurityContextCallable(@Nullable SecurityContext securityContext, Callable<R> delegate) {
			this.securityContext = (securityContext != null) ? securityContext
					: (this.strategy.isBound() ? this.strategy.getContext() : null);
			this.delegate = delegate;
		}

		@Override
		public R call() throws Exception {
			if (this.securityContext != null) {
				return callWhere(() -> this.securityContext, this.delegate);
			}
			else {
				return getSecuriyContextCarrier().call(new CallableOpOfCallable<R>(this.delegate));
			}
		}

	}

	/**
	 * A ScopedSecurityContextHolderStrategy-specific version of
	 * {@link org.springframework.security.concurrent.DelegatingSecurityContextRunnable
	 * DelegatingSecurityContextRunnable}.
	 *
	 */
	public static class DelegatingSecurityContextRunnable implements Runnable {

		private final @Nullable SecurityContext securityContext;

		private final Runnable delegate;

		private final ScopedSecurityContextHolderStrategy strategy = new ScopedSecurityContextHolderStrategy();

		public DelegatingSecurityContextRunnable(@Nullable SecurityContext securityContext, Runnable delegate) {
			this.securityContext = (securityContext != null) ? securityContext
					: (this.strategy.isBound() ? this.strategy.getContext() : null);
			this.delegate = delegate;
		}

		@Override
		public void run() {
			if (this.securityContext != null) {
				runWhere(() -> this.securityContext, this.delegate);
			}
			else {
				getSecuriyContextCarrier().run(this.delegate);
			}
		}

	}

}
