/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.oauth2.jwt;

import java.io.Serial;

/**
 * An exception thrown when a {@link JwtDecoder} or {@link ReactiveJwtDecoder}'s lazy
 * initialization fails.
 *
 * @author Josh Cummings
 * @since 5.6
 */
public class JwtDecoderInitializationException extends RuntimeException {

	@Serial
	private static final long serialVersionUID = 2786360018315628982L;

	public JwtDecoderInitializationException(String message, Throwable cause) {
		super(message, cause);
	}

}
