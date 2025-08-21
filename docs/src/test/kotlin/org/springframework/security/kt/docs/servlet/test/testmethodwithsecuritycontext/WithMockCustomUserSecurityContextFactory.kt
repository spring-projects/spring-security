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

package org.springframework.security.kt.docs.servlet.test.testmethodwithsecuritycontext;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.test.context.support.WithSecurityContextFactory

// tag::snippet[]
class WithMockCustomUserSecurityContextFactory : WithSecurityContextFactory<WithMockCustomUser> {
	override fun createSecurityContext(customUser: WithMockCustomUser): SecurityContext {
		val context = SecurityContextHolder.createEmptyContext()
		val principal = CustomUserDetails(customUser.name, customUser.username)
		val auth: Authentication =
				UsernamePasswordAuthenticationToken(principal, "password", principal.authorities)
		context.authentication = auth
		return context
	}
}
// end::snippet[]
