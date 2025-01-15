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

package org.springframework.security.authorization;

import java.io.Serial;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.util.Assert;

/**
 * An {@link AccessDeniedException} that contains the {@link AuthorizationResult}
 *
 * @author Marcus da Coregio
 * @since 6.3
 */
public class AuthorizationDeniedException extends AccessDeniedException implements AuthorizationResult {

	@Serial
	private static final long serialVersionUID = 3227305845919610459L;

	private final AuthorizationResult result;

	public AuthorizationDeniedException(String msg, AuthorizationResult authorizationResult) {
		super(msg);
		Assert.notNull(authorizationResult, "authorizationResult cannot be null");
		Assert.isTrue(!authorizationResult.isGranted(), "Granted authorization results are not supported");
		this.result = authorizationResult;
	}

	public AuthorizationDeniedException(String msg) {
		this(msg, new AuthorizationDecision(false));
	}

	public AuthorizationResult getAuthorizationResult() {
		return this.result;
	}

	@Override
	public boolean isGranted() {
		return false;
	}

}
