/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.web.authentication.ott;

import java.time.Duration;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.ott.GenerateOneTimeTokenRequest;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Default implementation of {@link GenerateOneTimeTokenRequestResolver}. Resolves
 * {@link GenerateOneTimeTokenRequest} from username parameter.
 *
 * @author Max Batischev
 * @since 6.5
 */
public final class DefaultGenerateOneTimeTokenRequestResolver implements GenerateOneTimeTokenRequestResolver {

	private static final Duration DEFAULT_EXPIRES_IN = Duration.ofMinutes(5);

	private Duration expiresIn = DEFAULT_EXPIRES_IN;

	@Override
	public GenerateOneTimeTokenRequest resolve(HttpServletRequest request) {
		String username = request.getParameter("username");
		if (!StringUtils.hasText(username)) {
			return null;
		}
		return new GenerateOneTimeTokenRequest(username, this.expiresIn);
	}

	/**
	 * Sets one-time token expiration time
	 * @param expiresIn one-time token expiration time
	 */
	public void setExpiresIn(Duration expiresIn) {
		Assert.notNull(expiresIn, "expiresIn cannot be null");
		this.expiresIn = expiresIn;
	}

}
