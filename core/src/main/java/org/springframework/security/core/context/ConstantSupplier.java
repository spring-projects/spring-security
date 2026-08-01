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
 * A {@link Supplier} of an already-materialized {@link SecurityContext}. Marker class so
 * {@link SecurityContextHolderThreadLocalAccessor} can inspect the value without
 * triggering deferred materialization.
 */
final class ConstantSupplier implements Supplier<SecurityContext> {

	private final SecurityContext context;

	ConstantSupplier(SecurityContext context) {
		Assert.notNull(context, "context cannot be null");
		this.context = context;
	}

	@Override
	public SecurityContext get() {
		return this.context;
	}

}
