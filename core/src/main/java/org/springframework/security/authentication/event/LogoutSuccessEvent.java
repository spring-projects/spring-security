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

package org.springframework.security.authentication.event;

import java.io.Serial;

import org.springframework.security.core.Authentication;

/**
 * Application event which indicates successful logout
 *
 * @author Onur Kagan Ozcan
 * @since 5.2.0
 */
public class LogoutSuccessEvent extends AbstractAuthenticationEvent {

	@Serial
	private static final long serialVersionUID = 5112491795571632311L;

	public LogoutSuccessEvent(Authentication authentication) {
		super(authentication);
	}

}
