/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.saml2.provider.service.web;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;

/**
 * A {@link Saml2AuthenticationRequestRepository} that stores all AuthnRequests in-memory.
 *
 * <p>
 * Note that because these values are in-memory, stale requests can accumulate due to
 * abandoned login attempts. As such, you should also have a process that performs a
 * periodic cleanup. You can do this with Spring with relative ease:
 *
 * <pre>

 * 	&#64;Component
 * 	public class InMemorySaml2AuthenticationRequestRepositoryEvicter {
 *  	private final InMemorySaml2AuthenticationRequestRepository requests;
 *
 *		&#64;Scheduled
 * 		public void evict() {
 * 	    	this.request.removeAuthenticationRequestsOlderThan(Instant.now().minusSeconds(600));
 * 		}
 * 	}
 * </pre>
 *
 * @author Josh Cummings
 * @since 6.3
 */
public final class InMemorySaml2AuthenticationRequestRepository
		implements Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> {

	private final Map<String, Entry> byRelayState = new ConcurrentHashMap<>();

	/**
	 * {@inheritDoc}
	 */
	@Override
	public AbstractSaml2AuthenticationRequest loadAuthenticationRequest(HttpServletRequest request) {
		String relayState = request.getParameter(Saml2ParameterNames.RELAY_STATE);
		if (this.byRelayState.containsKey(relayState)) {
			return this.byRelayState.get(relayState).request;
		}
		return null;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void saveAuthenticationRequest(AbstractSaml2AuthenticationRequest authenticationRequest,
			HttpServletRequest request, HttpServletResponse response) {
		this.byRelayState.put(authenticationRequest.getRelayState(), new Entry(authenticationRequest, Instant.now()));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public AbstractSaml2AuthenticationRequest removeAuthenticationRequest(HttpServletRequest request,
			HttpServletResponse response) {
		String relayState = request.getParameter(Saml2ParameterNames.RELAY_STATE);
		if (this.byRelayState.containsKey(relayState)) {
			return this.byRelayState.remove(relayState).request;
		}
		return null;
	}

	/**
	 * Remove any authentication requests that have been in-memory longer than the given
	 * {@code time}
	 * @param time the expiring value to apply
	 */
	public void removeAuthenticationRequestsOlderThan(Instant time) {
		Collection<String> toEvict = new ArrayList<>();
		for (Map.Entry<String, Entry> entry : this.byRelayState.entrySet()) {
			if (entry.getValue().added.isBefore(time)) {
				toEvict.add(entry.getKey());
			}
		}
		for (String key : toEvict) {
			this.byRelayState.remove(key);
		}
	}

	private record Entry(AbstractSaml2AuthenticationRequest request, Instant added) {

	}

}
