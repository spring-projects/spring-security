/*
 * Copyright 2010-2016 the original author or authors.
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
import java.util.LinkedHashMap;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.log.LogMessage;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.ELRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEditor;
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

	private final LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints;

	private AuthenticationEntryPoint defaultEntryPoint;

	public DelegatingAuthenticationEntryPoint(LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints) {
		this.entryPoints = entryPoints;
	}

	@Override
	public void commence(HttpServletRequest request, HttpServletResponse response,
			AuthenticationException authException) throws IOException, ServletException {
		for (RequestMatcher requestMatcher : this.entryPoints.keySet()) {
			logger.debug(LogMessage.format("Trying to match using %s", requestMatcher));
			if (requestMatcher.matches(request)) {
				AuthenticationEntryPoint entryPoint = this.entryPoints.get(requestMatcher);
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
	 */
	public void setDefaultEntryPoint(AuthenticationEntryPoint defaultEntryPoint) {
		this.defaultEntryPoint = defaultEntryPoint;
	}

	@Override
	public void afterPropertiesSet() {
		Assert.notEmpty(this.entryPoints, "entryPoints must be specified");
		Assert.notNull(this.defaultEntryPoint, "defaultEntryPoint must be specified");
	}

}
