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
 * A {@link GrantedAuthority} that includes timestamp information about when the authority
 * was issued and its optional validity window.
 *
 * @author Donghwan Kim
 * @since 7.1
 */
public final class TimestampedGrantedAuthority implements GrantedAuthority {

	private static final long serialVersionUID = -4215593566507954732L;

	private final String authority;

	private final Instant issuedAt;

	private final @Nullable Instant notBefore;

	private final @Nullable Instant expiresAt;

	private TimestampedGrantedAuthority(Builder builder, Instant issuedAt) {
		this.authority = builder.authority;
		this.issuedAt = issuedAt;
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
	 * Returns the instant after which this authority is not valid.
	 * @return the expires-at instant, or {@code null} if not specified
	 */
	public @Nullable Instant getExpiresAt() {
		return this.expiresAt;
	}

	@Override
	public boolean equals(@Nullable Object obj) {
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
		sb.append(", notBefore=").append(this.notBefore);
		sb.append(", expiresAt=").append(this.expiresAt);
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
		 * Sets the instant after which this authority is not valid.
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
		 */
		public TimestampedGrantedAuthority build() {
			Instant issuedAt = (this.issuedAt != null) ? this.issuedAt : Instant.now();
			if (this.notBefore != null && this.expiresAt != null) {
				Assert.isTrue(!this.notBefore.isAfter(this.expiresAt), "notBefore cannot be after expiresAt");
			}
			return new TimestampedGrantedAuthority(this, issuedAt);
		}

	}

}
