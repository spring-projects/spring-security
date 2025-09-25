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

package org.springframework.security.web.authentication;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.stream.Collectors;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.log.LogMessage;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.ELRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEditor;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.util.Assert;

/**
 * An {@code AuthenticationEntryPoint} which selects a concrete
 * {@code AuthenticationEntryPoint} based on a {@link RequestMatcher} evaluation.
 *
 * <p>
 * A configuration might look like this:
 * </p>
 *
 * <pre>
 * &lt;bean id=&quot;daep&quot; class=&quot;org.springframework.security.web.authentication.DelegatingAuthenticationEntryPoint&quot;&gt;
 *     &lt;constructor-arg&gt;
 *         &lt;map&gt;
 *             &lt;entry key=&quot;hasIpAddress('192.168.1.0/24') and hasHeader('User-Agent','Mozilla')&quot; value-ref=&quot;firstAEP&quot; /&gt;
 *             &lt;entry key=&quot;hasHeader('User-Agent','MSIE')&quot; value-ref=&quot;secondAEP&quot; /&gt;
 *         &lt;/map&gt;
 *     &lt;/constructor-arg&gt;
 *     &lt;property name=&quot;defaultEntryPoint&quot; ref=&quot;defaultAEP&quot;/&gt;
 * &lt;/bean&gt;
 * </pre>
 *
 * This example uses the {@link RequestMatcherEditor} which creates a
 * {@link ELRequestMatcher} instances for the map keys.
 *
 * @author Mike Wiesner
 * @since 3.0.2
 */
public class DelegatingAuthenticationEntryPoint implements AuthenticationEntryPoint, InitializingBean {

	private static final Log logger = LogFactory.getLog(DelegatingAuthenticationEntryPoint.class);

	private final List<RequestMatcherEntry<AuthenticationEntryPoint>> entryPoints;

	@SuppressWarnings("NullAway.Init")
	private AuthenticationEntryPoint defaultEntryPoint;

	/**
	 * Creates a new instance with the provided mappings.
	 * @param entryPoints the mapping of {@link RequestMatcher} to
	 * {@link AuthenticationEntryPoint}. Cannot be null or empty.
	 * @param defaultEntryPoint the default {@link AuthenticationEntryPoint}. Cannot be
	 * null.
	 */
	public DelegatingAuthenticationEntryPoint(AuthenticationEntryPoint defaultEntryPoint,
			RequestMatcherEntry<AuthenticationEntryPoint>... entryPoints) {
		Assert.notEmpty(entryPoints, "entryPoints cannot be empty");
		Assert.notNull(defaultEntryPoint, "defaultEntryPoint cannot be null");
		this.entryPoints = Arrays.asList(entryPoints);
		this.defaultEntryPoint = defaultEntryPoint;
	}

	/**
	 * Creates a new instance with the provided mappings.
	 * @param defaultEntryPoint the default {@link AuthenticationEntryPoint}. Cannot be
	 * null.
	 * @param entryPoints the mapping of {@link RequestMatcher} to
	 * {@link AuthenticationEntryPoint}. Cannot be null or empty.
	 */
	public DelegatingAuthenticationEntryPoint(AuthenticationEntryPoint defaultEntryPoint,
			List<RequestMatcherEntry<AuthenticationEntryPoint>> entryPoints) {
		Assert.notEmpty(entryPoints, "entryPoints cannot be empty");
		Assert.notNull(defaultEntryPoint, "defaultEntryPoint cannot be null");
		this.entryPoints = entryPoints;
		this.defaultEntryPoint = defaultEntryPoint;
	}

	/**
	 * Creates a new instance.
	 * @param entryPoints
	 * @deprecated Use
	 * {@link #DelegatingAuthenticationEntryPoint(AuthenticationEntryPoint, List)}
	 */
	@Deprecated(forRemoval = true)
	public DelegatingAuthenticationEntryPoint(LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints) {
		this.entryPoints = entryPoints.entrySet()
			.stream()
			.map((e) -> new RequestMatcherEntry<>(e.getKey(), e.getValue()))
			.collect(Collectors.toList());
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
		for (RequestMatcherEntry<AuthenticationEntryPoint> entry : this.entryPoints) {
			RequestMatcher requestMatcher = entry.getRequestMatcher();
			logger.debug(LogMessage.format("Trying to match using %s", requestMatcher));
			if (requestMatcher.matches(request)) {
				AuthenticationEntryPoint entryPoint = entry.getEntry();
				logger.debug(LogMessage.format("Match found! Executing %s", entryPoint));
				entryPoint.commence(request, response, authException);
				return;
			}
		}
		logger.debug(LogMessage.format("No match found. Using default entry point %s", this.defaultEntryPoint));
		// No EntryPoint matched, use defaultEntryPoint
		this.defaultEntryPoint.commence(request, response, authException);
	}

	/**
	 * EntryPoint which is used when no RequestMatcher returned true
	 * @deprecated Use
	 * {@link #DelegatingAuthenticationEntryPoint(AuthenticationEntryPoint, List)}
	 */
	@Deprecated(forRemoval = true)
	public void setDefaultEntryPoint(AuthenticationEntryPoint defaultEntryPoint) {
		this.defaultEntryPoint = defaultEntryPoint;
	}

	@Override
	public void afterPropertiesSet() {
		Assert.notEmpty(this.entryPoints, "entryPoints must be specified");
		Assert.notNull(this.defaultEntryPoint, "defaultEntryPoint must be specified");
	}

	/**
	 * Creates a new {@link Builder}
	 * @return the new {@link Builder}
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * Used to build a new instance of {@link DelegatingAuthenticationEntryPoint}.
	 *
	 * @author Rob Winch
	 * @since 7.0
	 */
	public static final class Builder {

		private @Nullable AuthenticationEntryPoint defaultEntryPoint;

		private List<RequestMatcherEntry<AuthenticationEntryPoint>> entryPoints = new ArrayList<RequestMatcherEntry<AuthenticationEntryPoint>>();

		/**
		 * Set the default {@link AuthenticationEntryPoint} if none match. The default is
		 * to use the first {@link AuthenticationEntryPoint} added in
		 * {@link #addEntryPointFor(AuthenticationEntryPoint, RequestMatcher)}.
		 * @param defaultEntryPoint the default {@link AuthenticationEntryPoint} to use.
		 * @return the {@link Builder} for further customization.
		 */
		public Builder defaultEntryPoint(@Nullable AuthenticationEntryPoint defaultEntryPoint) {
			this.defaultEntryPoint = defaultEntryPoint;
			return this;
		}

		/**
		 * Adds an {@link AuthenticationEntryPoint} for the provided
		 * {@link RequestMatcher}.
		 * @param entryPoint the {@link AuthenticationEntryPoint} to use. Cannot be null.
		 * @param requestMatcher the {@link RequestMatcher} to use. Cannot be null.
		 * @return the {@link Builder} for further customization.
		 */
		public Builder addEntryPointFor(AuthenticationEntryPoint entryPoint, RequestMatcher requestMatcher) {
			Assert.notNull(entryPoint, "entryPoint cannot be null");
			Assert.notNull(requestMatcher, "requestMatcher cannot be null");
			this.entryPoints.add(new RequestMatcherEntry<>(requestMatcher, entryPoint));
			return this;
		}

		/**
		 * Builds the {@link AuthenticationEntryPoint}. If the
		 * {@link #defaultEntryPoint(AuthenticationEntryPoint)} is not set, then the first
		 * {@link #addEntryPointFor(AuthenticationEntryPoint, RequestMatcher)} is used as
		 * the default. If the {@link #defaultEntryPoint(AuthenticationEntryPoint)} is not
		 * set and there is only a single
		 * {@link #addEntryPointFor(AuthenticationEntryPoint, RequestMatcher)}, then the
		 * {@link AuthenticationEntryPoint} is returned rather than wrapping it in
		 * {@link DelegatingAuthenticationEntryPoint}.
		 * @return the {@link AuthenticationEntryPoint} to use.
		 */
		public AuthenticationEntryPoint build() {
			AuthenticationEntryPoint defaultEntryPoint = this.defaultEntryPoint;
			if (defaultEntryPoint == null) {
				Assert.state(!this.entryPoints.isEmpty(), "entryPoints cannot be empty if defaultEntryPoint is null");
				AuthenticationEntryPoint firstAuthenticationEntryPoint = this.entryPoints.get(0).getEntry();
				if (this.entryPoints.size() == 1) {
					return firstAuthenticationEntryPoint;
				}
				defaultEntryPoint = firstAuthenticationEntryPoint;
			}
			else if (this.entryPoints.isEmpty()) {
				return defaultEntryPoint;
			}
			return new DelegatingAuthenticationEntryPoint(defaultEntryPoint, this.entryPoints);
		}

		private Builder() {
		}

	}

}
