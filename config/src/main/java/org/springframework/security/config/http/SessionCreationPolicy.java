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

package org.springframework.security.config.http;

import javax.servlet.http.HttpSession;

import org.springframework.security.core.context.SecurityContext;

/**
 * Specifies the various session creation policies for Spring Security.
 *
 * @author Luke Taylor
 * @since 3.1
 */
public enum SessionCreationPolicy {

	/**
	 * Always create an {@link HttpSession}
	 */
	ALWAYS,

	/**
	 * Spring Security will never create an {@link HttpSession}, but will use the
	 * {@link HttpSession} if it already exists
	 */
	NEVER,

	/**
	 * Spring Security will only create an {@link HttpSession} if required
	 */
	IF_REQUIRED,

	/**
	 * Spring Security will never create an {@link HttpSession} and it will never use it
	 * to obtain the {@link SecurityContext}
	 */
	STATELESS

}
