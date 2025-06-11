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

package org.springframework.security.kt.docs.servlet.test.testmethod

import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.config.core.MessageService
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder

/**
 * A message service for demonstrating test support for method-based security.
 */
// tag::authenticated[]
class HelloMessageService : MessageService {

	@PreAuthorize("isAuthenticated()")
	override fun getMessage(): String {
		val authentication: Authentication = SecurityContextHolder.getContext().authentication
		return "Hello $authentication"
	}

	@PreAuthorize("isAuthenticated()")
	override fun getJsrMessage(): String {
		val authentication = SecurityContextHolder.getContext().authentication
		return "Hello JSR $authentication"
	}
}
// end::authenticated[]
