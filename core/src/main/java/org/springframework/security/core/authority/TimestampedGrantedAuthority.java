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
 * Time-based implementation of {@link GrantedAuthority}.
 *
 * <p>
 * Represents an authority granted to the
 * {@link org.springframework.security.core.Authentication Authentication} object with
 * temporal constraints. This implementation allows authorities to have:
 * <ul>
 * <li>An issued-at timestamp indicating when the authority was granted</li>
 * <li>An optional not-before timestamp indicating when the authority becomes valid</li>
 * <li>An optional expires-at timestamp indicating when the authority expires</li>
 * </ul>
 *
 * <p>
 * This is particularly useful for:
 * <ul>
 * <li>Time-based authorization rules</li>
 * <li>OAuth 2.0 scopes with expiration</li>
 * <li>Temporary elevated privileges</li>
 * </ul>
 *
 * <p>
 * Example usage: <pre>
 * GrantedAuthority authority = TimestampedGrantedAuthority.withAuthority("profile:read")
 *     .issuedAt(Instant.now())
 *     .expiresAt(Instant.now().plusSeconds(300))
 *     .build();
 * </pre>
 *
 * @author Yoobin Yoon
 * @since 7.0
 */
public final class TimestampedGrantedAuthority implements GrantedAuthority {

	private static final long serialVersionUID = 1998010439847123984L;

	private final String authority;

	private final Instant issuedAt;

	private final @Nullable Instant notBefore;

	private final @Nullable Instant expiresAt;

	@SuppressWarnings("NullAway")
	private TimestampedGrantedAuthority(Builder builder) {
		this.authority = builder.authority;
		this.issuedAt = builder.issuedAt;
		this.notBefore = builder.notBefore;
		this.expiresAt = builder.expiresAt;
	}

	/**
	 * Creates a new {@link Builder} with the specified authority.
	 * @param authority the authority value (must not be null or empty)
	 * @return a new {@link Builder}
	 */
	public static Builder withAuthority(String authority) {
		return new Builder(authority);
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

	/**
	 * Returns the instant before which this authority is not valid.
	 * @return the not-before instant, or {@code null} if not specified
	 */
	public @Nullable Instant getNotBefore() {
		return this.notBefore;
	}

	/**
	 * Returns the instant when this authority expires.
	 * @return the expires-at instant, or {@code null} if not specified
	 */
	public @Nullable Instant getExpiresAt() {
		return this.expiresAt;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj instanceof TimestampedGrantedAuthority tga) {
			return this.authority.equals(tga.authority) && this.issuedAt.equals(tga.issuedAt)
					&& Objects.equals(this.notBefore, tga.notBefore) && Objects.equals(this.expiresAt, tga.expiresAt);
		}
		return false;
	}

	@Override
	public int hashCode() {
		return Objects.hash(this.authority, this.issuedAt, this.notBefore, this.expiresAt);
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		sb.append("TimestampedGrantedAuthority [");
		sb.append("authority=").append(this.authority);
		sb.append(", issuedAt=").append(this.issuedAt);
		if (this.notBefore != null) {
			sb.append(", notBefore=").append(this.notBefore);
		}
		if (this.expiresAt != null) {
			sb.append(", expiresAt=").append(this.expiresAt);
		}
		sb.append("]");
		return sb.toString();
	}

	/**
	 * Builder for {@link TimestampedGrantedAuthority}.
	 */
	public static final class Builder {

		private final String authority;

		private @Nullable Instant issuedAt;

		private @Nullable Instant notBefore;

		private @Nullable Instant expiresAt;

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
		 * Sets the instant before which this authority is not valid.
		 * @param notBefore the not-before instant
		 * @return this builder
		 */
		public Builder notBefore(Instant notBefore) {
			Assert.notNull(notBefore, "notBefore cannot be null");
			this.notBefore = notBefore;
			return this;
		}

		/**
		 * Sets the instant when this authority expires.
		 * @param expiresAt the expires-at instant
		 * @return this builder
		 */
		public Builder expiresAt(Instant expiresAt) {
			Assert.notNull(expiresAt, "expiresAt cannot be null");
			this.expiresAt = expiresAt;
			return this;
		}

		/**
		 * Builds a new {@link TimestampedGrantedAuthority}.
		 * <p>
		 * If {@code issuedAt} is not set, it defaults to {@link Instant#now()}.
		 * @return a new {@link TimestampedGrantedAuthority}
		 * @throws IllegalArgumentException if temporal constraints are invalid
		 */
		public TimestampedGrantedAuthority build() {
			if (this.issuedAt == null) {
				this.issuedAt = Instant.now();
			}
			if (this.notBefore != null && this.notBefore.isBefore(this.issuedAt)) {
				throw new IllegalArgumentException("notBefore must not be before issuedAt");
			}
			if (this.expiresAt != null && this.expiresAt.isBefore(this.issuedAt)) {
				throw new IllegalArgumentException("expiresAt must not be before issuedAt");
			}
			if (this.notBefore != null && this.expiresAt != null && this.expiresAt.isBefore(this.notBefore)) {
				throw new IllegalArgumentException("expiresAt must not be before notBefore");
			}

			return new TimestampedGrantedAuthority(this);
		}

	}

}
