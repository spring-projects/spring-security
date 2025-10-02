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

import java.util.Objects;

import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.util.Assert;

/**
 * An error when the requirements of {@link RequiredFactor} are not met.
 *
 * @author Rob Winch
 * @since 7.0
 */
public class RequiredFactorError {

	private final RequiredFactor requiredFactor;

	private final Reason reason;

	RequiredFactorError(RequiredFactor requiredFactor, Reason reason) {
		Assert.notNull(requiredFactor, "RequiredFactor must not be null");
		Assert.notNull(reason, "Reason must not be null");
		if (reason == Reason.EXPIRED && requiredFactor.getValidDuration() == null) {
			throw new IllegalArgumentException(
					"If expired, RequiredFactor.getValidDuration() must not be null. Got " + requiredFactor);
		}
		this.requiredFactor = requiredFactor;
		this.reason = reason;
	}

	public RequiredFactor getRequiredFactor() {
		return this.requiredFactor;
	}

	/**
	 * True if not {@link #isMissing()} but was older than the
	 * {@link RequiredFactor#getValidDuration()}.
	 * @return true if expired, else false
	 */
	public boolean isExpired() {
		return this.reason == Reason.EXPIRED;
	}

	/**
	 * True if no {@link FactorGrantedAuthority#getAuthority()} on the
	 * {@link org.springframework.security.core.Authentication} matched
	 * {@link RequiredFactor#getAuthority()}.
	 * @return true if missing, else false.
	 */
	public boolean isMissing() {
		return this.reason == Reason.MISSING;
	}

	@Override
	public boolean equals(Object o) {
		if (o == null || getClass() != o.getClass()) {
			return false;
		}
		RequiredFactorError that = (RequiredFactorError) o;
		return Objects.equals(this.requiredFactor, that.requiredFactor) && this.reason == that.reason;
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.requiredFactor, this.reason);
	}

	@Override
	public String toString() {
		return "RequiredFactorError{" + "requiredFactor=" + this.requiredFactor + ", reason=" + this.reason + '}';
	}

	public static RequiredFactorError createMissing(RequiredFactor requiredFactor) {
		return new RequiredFactorError(requiredFactor, Reason.MISSING);
	}

	public static RequiredFactorError createExpired(RequiredFactor requiredFactor) {
		return new RequiredFactorError(requiredFactor, Reason.EXPIRED);
	}

	/**
	 * The reason that the error occurred.
	 *
	 * @author Rob Winch
	 * @since 7.0
	 */
	private enum Reason {

		/**
		 * The authority was missing.
		 * @see #isMissing()
		 */
		MISSING,
		/**
		 * The authority was considered expired.
		 * @see #isExpired()
		 */
		EXPIRED

	}

}
