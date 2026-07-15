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

import org.springframework.util.Assert;

/**
 * Wraps a {@link Supplier} to reject {@code null} results. Marker class so
 * {@link SecurityContextHolderStrategy} can skip re-wrapping on round-trip — without it,
 * {@code setDeferredContext(getDeferredContext())} would accumulate one wrapper per call.
 */
final class NotNullSupplier implements Supplier<SecurityContext> {

	private final Supplier<SecurityContext> delegate;

	NotNullSupplier(Supplier<SecurityContext> delegate) {
		Assert.notNull(delegate, "delegate cannot be null");
		this.delegate = delegate;
	}

	@Override
	public SecurityContext get() {
		SecurityContext result = this.delegate.get();
		Assert.notNull(result, "A Supplier<SecurityContext> returned null and is not allowed.");
		return result;
	}

}
