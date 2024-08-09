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

package org.springframework.security.authentication.passwordless.ott;

import java.time.Clock;
import java.time.Instant;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Provides an in-memory implementation of the OneTimeTokenService interface. Note that
 * this implementation does not clear the tokens if they are not used.
 *
 * @author Marcus da Coregio
 * @since 6.4
 */
public class InMemoryOneTimeTokenService implements OneTimeTokenService {

	private final Map<String, OneTimeToken> oneTimeTokenByToken = new ConcurrentHashMap<>();

	private final Clock clock = Clock.systemUTC();

	@Override
	public OneTimeToken generate(OneTimeTokenAuthenticationRequest request) {
		String token = UUID.randomUUID().toString();
		Instant fiveMinutesFromNow = this.clock.instant().plusSeconds(300);
		OneTimeToken ott = new DefaultOneTimeToken(token, request.getUsername(), fiveMinutesFromNow);
		this.oneTimeTokenByToken.put(token, ott);
		return ott;
	}

	@Override
	public OneTimeToken consume(OneTimeTokenAuthenticationToken authenticationToken) {
		OneTimeToken ott = this.oneTimeTokenByToken.remove(authenticationToken.getToken());
		if (ott == null || isExpired(ott)) {
			return null;
		}
		return ott;
	}

	private boolean isExpired(OneTimeToken ott) {
		return this.clock.instant().isAfter(ott.getExpireAt());
	}

}
