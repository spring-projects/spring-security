/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.authentication.event;

import org.springframework.security.core.Authentication;

/**
 * The application event which indicates successful logout.
 *
 * @author Kazuki Shimizu
 * @since 4.2
 */
public class LogoutSuccessEvent extends AbstractAuthenticationEvent {

	/**
	 * Constructs a new logout success event.
	 *
	 * @param authentication the authentication object
	 */
	public LogoutSuccessEvent(Authentication authentication) {
		super(authentication);
	}

}