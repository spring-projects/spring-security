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

import java.time.Duration;
import java.util.Objects;

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.FactorGrantedAuthority;
import org.springframework.util.Assert;

/**
 * The requirements for an {@link GrantedAuthority} to be considered a valid factor.
 *
 * <ul>
 * <li>If the {@link #getAuthority()} is specified, then it must match
 * {@link GrantedAuthority#getAuthority()}</li>
 * <li>If {@link #getValidDuration()} is specified, the matching {@link GrantedAuthority}
 * must be of type {@link FactorGrantedAuthority} and
 * {@link FactorGrantedAuthority#getIssuedAt()} must be such that it is not considered
 * expired when compared to {@link #getValidDuration()}.</li>
 * </ul>
 *
 * @author Rob Winch
 * @since 7.0
 */
public final class RequiredFactor {

	private final String authority;

	private final @Nullable Duration validDuration;

	private RequiredFactor(String authority, @Nullable Duration validDuration) {
		Assert.notNull(authority, "authority cannot be null");
		this.authority = authority;
		this.validDuration = validDuration;
	}

	/**
	 * The expected {@link GrantedAuthority#getAuthority()}.
	 * @return the authority.
	 */
	public String getAuthority() {
		return this.authority;
	}

	/**
	 * How long the
	 * {@link org.springframework.security.core.authority.FactorGrantedAuthority} is valid
	 * for.
	 * @return
	 */
	public @Nullable Duration getValidDuration() {
		return this.validDuration;
	}

	@Override
	public boolean equals(Object o) {
		if (!(o instanceof RequiredFactor that)) {
			return false;
		}
		return Objects.equals(this.authority, that.authority) && Objects.equals(this.validDuration, that.validDuration);
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.authority, this.validDuration);
	}

	@Override
	public String toString() {
		return "RequiredFactor [authority=" + this.authority + ", validDuration=" + this.validDuration + "]";
	}

	/**
	 * Creates a {@link Builder} with the specified authority.
	 * @param authority the authority.
	 * @return the builder.
	 */
	public static Builder withAuthority(String authority) {
		return builder().authority(authority);
	}

	/**
	 * Creates a new {@link Builder}.
	 * @return
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * A builder for {@link RequiredFactor}.
	 *
	 * @author Rob Winch
	 * @since 7.0
	 */
	public static class Builder {

		private @Nullable String authority;

		private @Nullable Duration validDuration;

		/**
		 * Sets the required authority.
		 * @param authority the authority.
		 * @return the builder.
		 */
		public Builder authority(String authority) {
			this.authority = authority;
			return this;
		}

		/**
		 * Sets the optional {@link Duration} of time that the {@link RequiredFactor} is
		 * valid for.
		 * @param validDuration the {@link Duration}.
		 * @return
		 */
		public Builder validDuration(Duration validDuration) {
			this.validDuration = validDuration;
			return this;
		}

		/**
		 * Builds a new instance.
		 * @return
		 */
		public RequiredFactor build() {
			Assert.notNull(this.authority, "authority cannot be null");
			return new RequiredFactor(this.authority, this.validDuration);
		}

	}

}
