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

package org.springframework.security.saml2.provider.service.web;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.cache.Cache;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.provider.service.authentication.AbstractSaml2AuthenticationRequest;
import org.springframework.util.Assert;

/**
 * A cache-based {@link Saml2AuthenticationRequestRepository}. This can be handy when you
 * are dropping requests due to using SameSite=Strict and the previous session is lost.
 *
 * <p>
 * On the other hand, this presents a tradeoff where the application can only tell that
 * the given authentication request was created by this application, but cannot guarantee
 * that it was for the user trying to log in. Please see the reference for details.
 *
 * @author Josh Cummings
 * @since 6.5
 */
public final class CacheSaml2AuthenticationRequestRepository
		implements Saml2AuthenticationRequestRepository<AbstractSaml2AuthenticationRequest> {

	private Cache cache = new ConcurrentMapCache("authentication-requests");

	@Override
	public AbstractSaml2AuthenticationRequest loadAuthenticationRequest(HttpServletRequest request) {
		String relayState = request.getParameter(Saml2ParameterNames.RELAY_STATE);
		Assert.notNull(relayState, "relayState must not be null");
		return this.cache.get(relayState, AbstractSaml2AuthenticationRequest.class);
	}

	@Override
	public void saveAuthenticationRequest(AbstractSaml2AuthenticationRequest authenticationRequest,
			HttpServletRequest request, HttpServletResponse response) {
		String relayState = request.getParameter(Saml2ParameterNames.RELAY_STATE);
		Assert.notNull(relayState, "relayState must not be null");
		this.cache.put(relayState, authenticationRequest);
	}

	@Override
	public AbstractSaml2AuthenticationRequest removeAuthenticationRequest(HttpServletRequest request,
			HttpServletResponse response) {
		String relayState = request.getParameter(Saml2ParameterNames.RELAY_STATE);
		Assert.notNull(relayState, "relayState must not be null");
		AbstractSaml2AuthenticationRequest authenticationRequest = this.cache.get(relayState,
				AbstractSaml2AuthenticationRequest.class);
		if (authenticationRequest == null) {
			return null;
		}
		this.cache.evict(relayState);
		return authenticationRequest;
	}

	/**
	 * Use this {@link Cache} instance. The default is an in-memory cache, which means it
	 * won't work in a clustered environment. Instead, replace it here with a distributed
	 * cache.
	 * @param cache the {@link Cache} instance to use
	 */
	public void setCache(Cache cache) {
		this.cache = cache;
	}

}
