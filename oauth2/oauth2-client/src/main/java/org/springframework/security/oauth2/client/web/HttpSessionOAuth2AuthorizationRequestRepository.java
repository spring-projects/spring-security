/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.oauth2.client.web;

import java.io.Serializable;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;

/**
 * An implementation of an {@link AuthorizationRequestRepository} that stores
 * {@link OAuth2AuthorizationRequest} in the {@code HttpSession}.
 * <p>
 * <b>NOTE:</b> {@link OAuth2AuthorizationRequest}s expire after two minutes, the default
 * duration can be configured via
 * {@link #setOAuth2AuthorizationRequestExpiresIn(Duration)}.
 *
 * @author Joe Grandja
 * @author Rob Winch
 * @author Craig Andrews
 * @since 5.0
 * @see AuthorizationRequestRepository
 * @see OAuth2AuthorizationRequest
 */
public final class HttpSessionOAuth2AuthorizationRequestRepository
		implements AuthorizationRequestRepository<OAuth2AuthorizationRequest> {

	private static final String DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME = HttpSessionOAuth2AuthorizationRequestRepository.class
			.getName() + ".AUTHORIZATION_REQUEST";

	private final String sessionAttributeName = DEFAULT_AUTHORIZATION_REQUEST_ATTR_NAME;

	private Clock clock = Clock.systemUTC();

	private Duration oAuth2AuthorizationRequestExpiresIn = Duration.ofSeconds(120);

	@Override
	public OAuth2AuthorizationRequest loadAuthorizationRequest(HttpServletRequest request) {
		Assert.notNull(request, "request cannot be null");
		String stateParameter = this.getStateParameter(request);
		if (stateParameter == null) {
			return null;
		}
		Map<String, WrappedWithCreated<OAuth2AuthorizationRequest>> authorizationRequests = this
				.getAuthorizationRequests(request);
		WrappedWithCreated<OAuth2AuthorizationRequest> wrappedWithCreated = authorizationRequests.get(stateParameter);
		return (wrappedWithCreated != null) ? wrappedWithCreated.wrapped : null;
	}

	@Override
	public void saveAuthorizationRequest(OAuth2AuthorizationRequest authorizationRequest, HttpServletRequest request,
			HttpServletResponse response) {
		Assert.notNull(request, "request cannot be null");
		Assert.notNull(response, "response cannot be null");
		if (authorizationRequest == null) {
			this.removeAuthorizationRequest(request, response);
			return;
		}
		String state = authorizationRequest.getState();
		Assert.hasText(state, "authorizationRequest.state cannot be empty");
		Map<String, WrappedWithCreated<OAuth2AuthorizationRequest>> authorizationRequests = this
				.getAuthorizationRequests(request);
		authorizationRequests.put(state, new WrappedWithCreated<>(this.clock.instant(), authorizationRequest));
		request.getSession().setAttribute(this.sessionAttributeName, authorizationRequests);
	}

	@Override
	public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request) {
		Assert.notNull(request, "request cannot be null");
		String stateParameter = this.getStateParameter(request);
		if (stateParameter == null) {
			return null;
		}
		Map<String, WrappedWithCreated<OAuth2AuthorizationRequest>> authorizationRequests = this
				.getAuthorizationRequests(request);
		WrappedWithCreated<OAuth2AuthorizationRequest> wrappedWithCreatedOriginalRequest = authorizationRequests
				.remove(stateParameter);
		if (!authorizationRequests.isEmpty()) {
			request.getSession().setAttribute(this.sessionAttributeName, authorizationRequests);
		}
		else {
			request.getSession().removeAttribute(this.sessionAttributeName);
		}
		return (wrappedWithCreatedOriginalRequest != null) ? wrappedWithCreatedOriginalRequest.wrapped : null;
	}

	@Override
	public OAuth2AuthorizationRequest removeAuthorizationRequest(HttpServletRequest request,
			HttpServletResponse response) {
		Assert.notNull(response, "response cannot be null");
		return this.removeAuthorizationRequest(request);
	}

	/**
	 * Gets the state parameter from the {@link HttpServletRequest}
	 * @param request the request to use
	 * @return the state parameter or null if not found
	 */
	private String getStateParameter(HttpServletRequest request) {
		return request.getParameter(OAuth2ParameterNames.STATE);
	}

	/**
	 * Gets a non-null and mutable map of {@link OAuth2AuthorizationRequest#getState()} to
	 * an {@link OAuth2AuthorizationRequest}
	 * @param request
	 * @return a non-null and mutable map of {@link OAuth2AuthorizationRequest#getState()}
	 * to an {@link OAuth2AuthorizationRequest}.
	 */
	private Map<String, WrappedWithCreated<OAuth2AuthorizationRequest>> getAuthorizationRequests(
			HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		Map<String, WrappedWithCreated<OAuth2AuthorizationRequest>> authorizationRequests = (session != null)
				? (Map<String, WrappedWithCreated<OAuth2AuthorizationRequest>>) session
						.getAttribute(this.sessionAttributeName)
				: null;
		if (authorizationRequests == null) {
			return new HashMap<>();
		}
		// remove expired entries
		authorizationRequests.entrySet().removeIf((entry) -> entry.getValue().created
				.isBefore(this.clock.instant().minus(this.oAuth2AuthorizationRequestExpiresIn)));
		return authorizationRequests;
	}

	/**
	 * Sets the {@link Clock} used in {@link Instant#now(Clock)} when setting the instant
	 * created for {@link OAuth2AuthorizationRequest}.
	 * @param clock the clock
	 * @since 5.5
	 */
	public void setClock(Clock clock) {
		Assert.notNull(clock, "clock cannot be null");
		this.clock = clock;
	}

	/**
	 * Sets the {@link Duration} for which {@link OAuth2AuthorizationRequest} should
	 * expire.
	 * @param oAuth2AuthorizationRequestExpiresIn the {@link Duration} a
	 * {@link OAuth2AuthorizationRequest} is considered not expired. Must not be negative.
	 * @since 5.5
	 */
	public void setOAuth2AuthorizationRequestExpiresIn(Duration oAuth2AuthorizationRequestExpiresIn) {
		Assert.notNull(oAuth2AuthorizationRequestExpiresIn, "oAuth2AuthorizationRequestExpiresIn cannot be null");
		Assert.state(!oAuth2AuthorizationRequestExpiresIn.isNegative(),
				"oAuth2AuthorizationRequestExpiresIn cannot be negative");
		this.oAuth2AuthorizationRequestExpiresIn = oAuth2AuthorizationRequestExpiresIn;
	}

	private static final class WrappedWithCreated<T extends Serializable> implements Serializable {

		private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

		private final Instant created;

		private final T wrapped;

		private WrappedWithCreated(Instant created, T wrapped) {
			super();
			this.created = created;
			Assert.notNull(wrapped, "wrapped cannot be null");
			this.wrapped = wrapped;
		}

	}

}
