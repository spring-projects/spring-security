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

package org.springframework.security.authorization;

import java.util.Collections;
import java.util.List;

import org.springframework.util.Assert;

/**
 * An {@link AuthorizationResult} that contains {@link RequiredFactorError}.
 *
 * @author Rob Winch
 * @since 7.0
 */
public class FactorAuthorizationDecision implements AuthorizationResult {

	private final List<RequiredFactorError> factorErrors;

	/**
	 * Creates a new instance.
	 * @param factorErrors the {@link RequiredFactorError}. If empty, {@link #isGranted()}
	 * returns true. Cannot be null or contain empty values.
	 */
	public FactorAuthorizationDecision(List<RequiredFactorError> factorErrors) {
		Assert.notNull(factorErrors, "factorErrors cannot be null");
		Assert.noNullElements(factorErrors, "factorErrors must not contain null elements");
		this.factorErrors = Collections.unmodifiableList(factorErrors);
	}

	/**
	 * The specified {@link RequiredFactorError}s
	 * @return the errors. Cannot be null or contain null values.
	 */
	public List<RequiredFactorError> getFactorErrors() {
		return this.factorErrors;
	}

	/**
	 * Returns {@code getFactorErrors().isEmpty()}.
	 * @return
	 */
	@Override
	public boolean isGranted() {
		return this.factorErrors.isEmpty();
	}

}
