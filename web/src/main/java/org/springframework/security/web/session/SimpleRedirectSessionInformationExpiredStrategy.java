/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.web.session;

import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;

/**
 * Performs a redirect to a fixed URL when an expired session is detected by the
 * {@code ConcurrentSessionFilter}.
 *
 * @author Marten Deinum
 * @since 4.2.0
 */
public final class SimpleRedirectSessionInformationExpiredStrategy implements SessionInformationExpiredStrategy {
	private final Log logger = LogFactory.getLog(getClass());
	private final String destinationUrl;
	private final RedirectStrategy redirectStrategy;

	public SimpleRedirectSessionInformationExpiredStrategy(String invalidSessionUrl) {
		this(invalidSessionUrl, new DefaultRedirectStrategy());
	}

	public SimpleRedirectSessionInformationExpiredStrategy(String invalidSessionUrl, RedirectStrategy redirectStrategy) {
		Assert.isTrue(UrlUtils.isValidRedirectUrl(invalidSessionUrl),
				"url must start with '/' or with 'http(s)'");
		this.destinationUrl=invalidSessionUrl;
		this.redirectStrategy=redirectStrategy;
	}

	public void onExpiredSessionDetected(SessionInformationExpiredEvent event) throws IOException {
		logger.debug("Redirecting to '" + destinationUrl + "'");
		redirectStrategy.sendRedirect(event.getRequest(), event.getResponse(), destinationUrl);
	}

}
