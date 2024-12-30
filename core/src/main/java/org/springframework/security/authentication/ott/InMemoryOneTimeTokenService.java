/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.authentication.ott;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.lang.NonNull;
import org.springframework.util.Assert;

/**
 * Provides an in-memory implementation of the {@link OneTimeTokenService} interface that
 * uses a {@link ConcurrentHashMap} to store the generated {@link OneTimeToken}. A random
 * {@link UUID} is used as the token value. A clean-up of the expired tokens is made if
 * there is more or equal than 100 tokens stored in the map.
 *
 * @author Marcus da Coregio
 * @since 6.4
 */
public final class InMemoryOneTimeTokenService implements OneTimeTokenService {

	private final Map<String, OneTimeToken> oneTimeTokenByToken = new ConcurrentHashMap<>();

	private Clock clock = Clock.systemUTC();

	@Override
	@NonNull
	public OneTimeToken generate(GenerateOneTimeTokenRequest request) {
		String token = UUID.randomUUID().toString();
		Instant fiveMinutesFromNow = this.clock.instant().plusSeconds(300);
		OneTimeToken ott = new DefaultOneTimeToken(token, request.getUsername(), fiveMinutesFromNow);
		this.oneTimeTokenByToken.put(token, ott);
		cleanExpiredTokensIfNeeded();
		return ott;
	}

	@Override
	public OneTimeToken consume(OneTimeTokenAuthenticationToken authenticationToken) {
		OneTimeToken ott = this.oneTimeTokenByToken.remove(authenticationToken.getTokenValue());
		if (ott == null || isExpired(ott)) {
			return null;
		}
		return ott;
	}

	private void cleanExpiredTokensIfNeeded() {
		if (this.oneTimeTokenByToken.size() < 100) {
			return;
		}
		for (Map.Entry<String, OneTimeToken> entry : this.oneTimeTokenByToken.entrySet()) {
			if (isExpired(entry.getValue())) {
				this.oneTimeTokenByToken.remove(entry.getKey());
			}
		}
	}

	private boolean isExpired(OneTimeToken ott) {
		return this.clock.instant().isAfter(ott.getExpiresAt());
	}

	/**
	 * Sets the {@link Clock} used when generating one-time token and checking token
	 * expiry.
	 * @param clock the clock
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}

}
