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

package org.springframework.security.oauth2.jwt;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.Callable;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicBoolean;

import com.nimbusds.jose.jwk.JWK;

import org.springframework.cache.Cache;
import org.springframework.cache.support.SimpleValueWrapper;
import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * An {@link OAuth2TokenValidator} that mitigates DPoP Proof Replay.
 *
 * <p>
 * This validator mitigates DPoP Proof Replay by ensuring the DPoP Proof:
 * <ul>
 * <li>contains the {@code iat} (issued at) claim, and it's within an acceptable time
 * window (configured via {@link #setClockSkew(Duration)})</li>
 * <li>contains the {@code jti} (JWT ID) claim, and it has not been used previously</li>
 * </ul>
 *
 * <p>
 * This implementation uses a {@link Cache} to store the {@code jti} claim (along with
 * other information in {@link CacheValue CacheValue}) to enforce single-use. The
 * {@code jti} is retained in the cache until the DPoP Proof expires, which is calculated
 * as {@code iat + clockSkew}.
 *
 * @author Joe Grandja
 * @since 6.5.12
 * @see OAuth2TokenValidator
 * @see DPoPProofJwtDecoderFactory
 * @see <a target="_blank" href=
 * "https://datatracker.ietf.org/doc/html/rfc9449#section-11.1">Section 11.1. DPoP Proof
 * Replay</a>
 */
public final class DPoPProofReplayValidator implements OAuth2TokenValidator<Jwt> {

	private final Cache cache;

	private Duration clockSkew = Duration.ofSeconds(30);

	private Clock clock = Clock.systemUTC();

	/**
	 * Constructs a {@code DPoPProofReplayValidator} using the provided parameters.
	 * @param cache the {@link Cache} used to store {@link CacheValue} which contains
	 * information of the used DPoP Proof {@link Jwt}'s
	 */
	public DPoPProofReplayValidator(Cache cache) {
		Assert.notNull(cache, "cache cannot be null");
		this.cache = cache;
	}

	@Override
	public OAuth2TokenValidatorResult validate(Jwt jwt) {
		Assert.notNull(jwt, "DPoP proof jwt cannot be null");
		String jti = jwt.getId();
		if (!StringUtils.hasText(jti)) {
			OAuth2Error error = createOAuth2Error("jti claim is required.");
			return OAuth2TokenValidatorResult.failure(error);
		}

		Instant issuedAt = jwt.getIssuedAt();
		if (issuedAt == null) {
			OAuth2Error error = createOAuth2Error("iat claim is required.");
			return OAuth2TokenValidatorResult.failure(error);
		}

		// Ensure acceptable time window
		Instant now = Instant.now(this.clock);
		Instant notBefore = now.minus(this.clockSkew);
		Instant notAfter = now.plus(this.clockSkew);
		if (issuedAt.isBefore(notBefore) || issuedAt.isAfter(notAfter)) {
			OAuth2Error error = createOAuth2Error("iat claim is invalid.");
			return OAuth2TokenValidatorResult.failure(error);
		}

		String jwkThumbprint;
		try {
			@SuppressWarnings("unchecked")
			Map<String, Object> jwkJson = (Map<String, Object>) jwt.getHeaders().get("jwk");
			JWK jwk = JWK.parse(jwkJson);
			jwkThumbprint = jwk.computeThumbprint().toString();
		}
		catch (Exception ex) {
			OAuth2Error error = createOAuth2Error("jwk header is missing or invalid.");
			return OAuth2TokenValidatorResult.failure(error);
		}

		String jtiHash;
		try {
			jtiHash = computeSHA256(jti);
		}
		catch (Exception ex) {
			OAuth2Error error = createOAuth2Error("jti claim is invalid.");
			return OAuth2TokenValidatorResult.failure(error);
		}

		Instant expiresAt = issuedAt.plus(this.clockSkew);
		CacheValue cacheValue = new CacheValue(issuedAt, expiresAt, jwkThumbprint);

		// Enforce single-use to protect against DPoP proof replay
		if (this.cache.putIfAbsent(jtiHash, cacheValue) != null) {
			// Already used or cache full or key limit reached
			OAuth2Error error = createOAuth2Error("jti claim is invalid or unable to cache.");
			return OAuth2TokenValidatorResult.failure(error);
		}
		return OAuth2TokenValidatorResult.success();
	}

	/**
	 * Sets the clock skew. The default is 30 seconds.
	 * @param clockSkew the clock skew
	 */
	public void setClockSkew(Duration clockSkew) {
		Assert.notNull(clockSkew, "clockSkew cannot be null");
		Assert.isTrue(clockSkew.getSeconds() >= 0, "clockSkew must be >= 0");
		this.clockSkew = clockSkew;
	}

	/**
	 * Sets the {@link Clock} used in {@link Instant#now(Clock)}.
	 * @param clock the clock
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}

	private static OAuth2Error createOAuth2Error(String reason) {
		return new OAuth2Error(OAuth2ErrorCodes.INVALID_DPOP_PROOF, reason, null);
	}

	private static String computeSHA256(String value) throws Exception {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(value.getBytes(StandardCharsets.UTF_8));
		return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
	}

	/**
	 * An in-memory {@link Cache} implementation backed by a {@link ConcurrentHashMap}.
	 *
	 * <p>
	 * <b>NOTE:</b> This implementation has limitations as it only works in a single-node
	 * setup. For production (and clustered) environments, it is recommended to use a
	 * distributed {@link Cache} implementation (e.g. Redis, Hazelcast, etc.).
	 *
	 * <p>
	 * This implementation can be fine-tuned based on the following configuration
	 * settings:
	 * <ul>
	 * <li>{@link #setMaxSize(int)} - Sets the maximum number of entries the cache can
	 * hold. The default is 100,000.</li>
	 * <li>{@link #setMaxRequestsPerKey(int)} - Sets the maximum number of requests
	 * allowed per {@link CacheValue#getJwkThumbprint() JWK thumbprint}. The default is
	 * 1000.</li>
	 * </ul>
	 */
	public static final class InMemoryCache implements Cache {

		private static final String DEFAULT_NAME = InMemoryCache.class.getName().concat(".DPOP-PROOF-CACHE");

		private static final int DEFAULT_MAX_SIZE = 100_000;

		private static final int DEFAULT_MAX_REQUESTS_PER_KEY = 1000;

		private static final int CLEANUP_INTERVAL_SECS = 10;

		private final ConcurrentMap<String, CacheValue> cache = new ConcurrentHashMap<>();

		private final ConcurrentMap<String, Integer> requestsPerKey = new ConcurrentHashMap<>();

		private final AtomicBoolean cleaning = new AtomicBoolean(false);

		private long lastCleanup = System.currentTimeMillis();

		private int maxSize = DEFAULT_MAX_SIZE;

		private int maxRequestsPerKey = DEFAULT_MAX_REQUESTS_PER_KEY;

		/**
		 * Returns the maximum number of entries the cache can hold.
		 * @return the maximum number of entries the cache can hold
		 */
		public int getMaxSize() {
			return this.maxSize;
		}

		/**
		 * Sets the maximum number of entries the cache can hold. The default is 100,000.
		 * @param maxSize the maximum number of entries the cache can hold
		 */
		public void setMaxSize(int maxSize) {
			Assert.isTrue(maxSize > 0, "maxSize must be > 0");
			this.maxSize = maxSize;
		}

		/**
		 * Returns the maximum number of requests allowed per
		 * {@link CacheValue#getJwkThumbprint() JWK thumbprint}.
		 * @return the maximum number of requests allowed per
		 * {@link CacheValue#getJwkThumbprint() JWK thumbprint}
		 */
		public int getMaxRequestsPerKey() {
			return this.maxRequestsPerKey;
		}

		/**
		 * Sets the maximum number of requests allowed per
		 * {@link CacheValue#getJwkThumbprint() JWK thumbprint}. The default is 1000.
		 * @param maxRequestsPerKey the maximum number of requests allowed per
		 * {@link CacheValue#getJwkThumbprint() JWK thumbprint}
		 */
		public void setMaxRequestsPerKey(int maxRequestsPerKey) {
			Assert.isTrue(maxRequestsPerKey > 0, "maxRequestsPerKey must be > 0");
			this.maxRequestsPerKey = maxRequestsPerKey;
		}

		@Override
		public String getName() {
			return DEFAULT_NAME;
		}

		@Override
		public Object getNativeCache() {
			return this.cache;
		}

		@Override
		public @Nullable ValueWrapper get(Object key) {
			Object value = this.cache.get(key);
			return (value != null) ? new SimpleValueWrapper(value) : null;
		}

		@SuppressWarnings("unchecked")
		@Override
		public <T> @Nullable T get(Object key, @Nullable Class<T> type) {
			Object value = this.cache.get(key);
			if (value != null && type != null && !type.isInstance(value)) {
				throw new IllegalStateException(
						"Cached value is not of required type [" + type.getName() + "]: " + value);
			}
			return (T) value;
		}

		@Override
		public <T> @Nullable T get(Object key, Callable<T> valueLoader) {
			throw new UnsupportedOperationException();
		}

		@Override
		public void put(Object key, Object value) {
			putIfAbsent(key, value);
		}

		@Override
		public @Nullable ValueWrapper putIfAbsent(Object key, Object value) {
			String jti = (String) key;
			CacheValue cacheValue = (CacheValue) value;

			cleanupIfNecessary();
			if (this.cache.size() >= this.maxSize) {
				// Force an immediate cleanup when we hit the limit before the cleanup
				// interval
				cleanup();
				if (this.cache.size() >= this.maxSize) {
					// Cache full - return non-null value
					return new SimpleValueWrapper(cacheValue);
				}
			}

			// Limit the number of requests per key
			AtomicBoolean limitExceeded = new AtomicBoolean(false);
			this.requestsPerKey.compute(cacheValue.jwkThumbprint, (k, v) -> {
				if (v != null && v >= this.maxRequestsPerKey) {
					limitExceeded.set(true);
					return v;
				}
				// Increment
				return (v != null) ? v + 1 : 1;
			});
			if (limitExceeded.get()) {
				// Key limit reached - return non-null value
				return new SimpleValueWrapper(cacheValue);
			}

			if (this.cache.putIfAbsent(jti, cacheValue) != null) {
				// jti exists - revert the increment and return non-null value
				this.requestsPerKey.computeIfPresent(cacheValue.jwkThumbprint, (k, v) -> (v > 1) ? v - 1 : null);
				return new SimpleValueWrapper(cacheValue);
			}

			return null;
		}

		@Override
		public void evict(Object key) {
		}

		@Override
		public void clear() {
		}

		private void cleanupIfNecessary() {
			long now = System.currentTimeMillis();
			long last = this.lastCleanup;
			if ((now - last) > (CLEANUP_INTERVAL_SECS * 1000)) {
				cleanup();
			}
		}

		private void cleanup() {
			if (this.cleaning.compareAndSet(false, true)) {
				try {
					Instant now = Instant.now();
					for (Map.Entry<String, CacheValue> entry : this.cache.entrySet()) {
						if (now.isAfter(entry.getValue().expiresAt)) {
							this.cache.remove(entry.getKey());
							this.requestsPerKey.computeIfPresent(entry.getValue().jwkThumbprint,
									(k, v) -> (v > 1) ? v - 1 : null);
						}
					}
					this.lastCleanup = System.currentTimeMillis();
				}
				finally {
					this.cleaning.set(false);
				}
			}
		}

	}

	/**
	 * A representation of the value to which the {@link Cache} maps a (hashed)
	 * {@code (jti)} claim as the key.
	 */
	public static final class CacheValue {

		private final Instant issuedAt;

		private final Instant expiresAt;

		private final String jwkThumbprint;

		/**
		 * Constructs a {@code CacheValue} using the provided parameters.
		 * @param issuedAt the issued at claim which identifies the time at which the DPoP
		 * Proof {@link Jwt} was issued
		 * @param expiresAt the expiration time when this {@code CacheValue} will be
		 * evicted from the cache
		 * @param jwkThumbprint the SHA-256 thumbprint of the public key of the JSON Web
		 * Key (JWK) corresponding to the key used to digitally sign the DPoP Proof
		 * {@link Jwt}
		 */
		public CacheValue(Instant issuedAt, Instant expiresAt, String jwkThumbprint) {
			Assert.notNull(issuedAt, "issuedAt cannot be null");
			Assert.notNull(expiresAt, "expiresAt cannot be null");
			Assert.hasText(jwkThumbprint, "jwkThumbprint cannot be empty");
			this.issuedAt = issuedAt;
			this.expiresAt = expiresAt;
			this.jwkThumbprint = jwkThumbprint;
		}

		/**
		 * Returns the issued at {@code (iat)} claim which identifies the time at which
		 * the DPoP Proof {@link Jwt} was issued.
		 * @return the issued at claim which identifies the time at which the DPoP Proof
		 * {@link Jwt} was issued
		 */
		public Instant getIssuedAt() {
			return this.issuedAt;
		}

		/**
		 * Returns the expiration time when this {@code CacheValue} will be evicted from
		 * the cache.
		 * @return the expiration time when this {@code CacheValue} will be evicted from
		 * the cache
		 */
		public Instant getExpiresAt() {
			return this.expiresAt;
		}

		/**
		 * Returns the SHA-256 thumbprint of the public key of the JSON Web Key (JWK)
		 * corresponding to the key used to digitally sign the DPoP Proof {@link Jwt}.
		 * @return the SHA-256 thumbprint of the public key of the JSON Web Key (JWK)
		 */
		public String getJwkThumbprint() {
			return this.jwkThumbprint;
		}

		@Override
		public boolean equals(Object obj) {
			if (obj == this) {
				return true;
			}
			if (obj == null || obj.getClass() != this.getClass()) {
				return false;
			}
			CacheValue that = (CacheValue) obj;
			return Objects.equals(this.issuedAt, that.issuedAt) && Objects.equals(this.expiresAt, that.expiresAt)
					&& Objects.equals(this.jwkThumbprint, that.jwkThumbprint);
		}

		@Override
		public int hashCode() {
			return Objects.hash(this.issuedAt, this.expiresAt, this.jwkThumbprint);
		}

	}

}
