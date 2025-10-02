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

package org.springframework.security.core.authority;

import java.time.Instant;
import java.util.Objects;

import org.jspecify.annotations.Nullable;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.Assert;

/**
 * A {@link GrantedAuthority} specifically used for indicating the factor used at time of
 * authentication.
 *
 * @author Yoobin Yoon
 * @author Rob Winch
 * @since 7.0
 */
public final class FactorGrantedAuthority implements GrantedAuthority {

	private static final long serialVersionUID = 1998010439847123984L;

	private final String authority;

	private final Instant issuedAt;

	@SuppressWarnings("NullAway")
	private FactorGrantedAuthority(String authority, Instant issuedAt) {
		Assert.notNull(authority, "authority cannot be null");
		Assert.notNull(issuedAt, "issuedAt cannot be null");
		this.authority = authority;
		this.issuedAt = issuedAt;
	}

	/**
	 * Creates a new {@link Builder} with the specified authority.
	 * @param authority the authority value (must not be null or empty)
	 * @return a new {@link Builder}
	 */
	public static Builder withAuthority(String authority) {
		return new Builder(authority);
	}

	/**
	 * Creates a new {@link Builder} with the specified factor which is automatically
	 * prefixed with "FACTOR_".
	 * @param factor the factor value which is automatically prefixed with "FACTOR_" (must
	 * not be null or empty)
	 * @return a new {@link Builder}
	 */
	public static Builder withFactor(String factor) {
		Assert.hasText(factor, "factor cannot be empty");
		Assert.isTrue(!factor.startsWith("FACTOR_"), () -> "factor cannot start with 'FACTOR_' got '" + factor + "'");
		return withAuthority("FACTOR_" + factor);
	}

	/**
	 * Shortcut for {@code withAuthority(authority).build()}.
	 * @param authority the authority value (must not be null or empty)
	 * @return a new {@link FactorGrantedAuthority}
	 */
	public static FactorGrantedAuthority fromAuthority(String authority) {
		return withAuthority(authority).build();
	}

	/**
	 * Shortcut for {@code withFactor(factor).build()}.
	 * @param factor the factor value which is automatically prefixed with "FACTOR_" (must
	 * not be null or empty)
	 * @return a new {@link FactorGrantedAuthority}
	 */
	public static FactorGrantedAuthority fromFactor(String factor) {
		return withFactor(factor).build();
	}

	@Override
	public String getAuthority() {
		return this.authority;
	}

	/**
	 * Returns the instant when this authority was issued.
	 * @return the issued-at instant
	 */
	public Instant getIssuedAt() {
		return this.issuedAt;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj instanceof FactorGrantedAuthority fga) {
			return this.authority.equals(fga.authority) && this.issuedAt.equals(fga.issuedAt);
		}
		return false;
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.authority, this.issuedAt);
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("FactorGrantedAuthority [");
		sb.append("authority=").append(this.authority);
		sb.append(", issuedAt=").append(this.issuedAt);
		sb.append("]");
		return sb.toString();
	}

	/**
	 * Builder for {@link FactorGrantedAuthority}.
	 */
	public static final class Builder {

		private final String authority;

		private @Nullable Instant issuedAt;

		private Builder(String authority) {
			Assert.hasText(authority, "A granted authority textual representation is required");
			this.authority = authority;
		}

		/**
		 * Sets the instant when this authority was issued.
		 * @param issuedAt the issued-at instant
		 * @return this builder
		 */
		public Builder issuedAt(Instant issuedAt) {
			Assert.notNull(issuedAt, "issuedAt cannot be null");
			this.issuedAt = issuedAt;
			return this;
		}

		/**
		 * Builds a new {@link FactorGrantedAuthority}.
		 * <p>
		 * If {@code issuedAt} is not set, it defaults to {@link Instant#now()}.
		 * @return a new {@link FactorGrantedAuthority}
		 * @throws IllegalArgumentException if temporal constraints are invalid
		 */
		public FactorGrantedAuthority build() {
			if (this.issuedAt == null) {
				this.issuedAt = Instant.now();
			}

			return new FactorGrantedAuthority(this.authority, this.issuedAt);
		}

	}

}
