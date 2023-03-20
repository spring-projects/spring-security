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

package org.springframework.security.web.context;

import java.util.function.Supplier;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolderStrategy;

/**
 * @author Steve Riesenberg
 * @since 5.8
 */
final class SupplierDeferredSecurityContext implements DeferredSecurityContext {

	private static final Log logger = LogFactory.getLog(SupplierDeferredSecurityContext.class);

	private final Supplier<SecurityContext> supplier;

	private final SecurityContextHolderStrategy strategy;

	private SecurityContext securityContext;

	private boolean missingContext;

	SupplierDeferredSecurityContext(Supplier<SecurityContext> supplier, SecurityContextHolderStrategy strategy) {
		this.supplier = supplier;
		this.strategy = strategy;
	}

	@Override
	public SecurityContext get() {
		init();
		return this.securityContext;
	}

	@Override
	public boolean isGenerated() {
		init();
		return this.missingContext;
	}

	private void init() {
		if (this.securityContext != null) {
			return;
		}

		this.securityContext = this.supplier.get();
		this.missingContext = (this.securityContext == null);
		if (this.missingContext) {
			this.securityContext = this.strategy.createEmptyContext();
			if (logger.isTraceEnabled()) {
				logger.trace(LogMessage.format("Created %s", this.securityContext));
			}
		}
	}

}
