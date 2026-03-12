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

package org.springframework.security.kt.docs.servlet.addingcustomfilter

import jakarta.servlet.Filter
import jakarta.servlet.FilterChain
import jakarta.servlet.ServletException
import jakarta.servlet.ServletRequest
import jakarta.servlet.ServletResponse
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.access.AccessDeniedException
import java.io.IOException

// tag::snippet[]
class TenantFilter : Filter {

	@Throws(IOException::class, ServletException::class)
	override fun doFilter(servletRequest: ServletRequest, servletResponse: ServletResponse, filterChain: FilterChain) {
		val request = servletRequest as HttpServletRequest
		val response = servletResponse as HttpServletResponse

		val tenantId = request.getHeader("X-Tenant-Id") // <1>
		val hasAccess = isUserAllowed(tenantId) // <2>
		if (hasAccess) {
			filterChain.doFilter(request, response) // <3>
			return
		}
		throw AccessDeniedException("Access denied") // <4>
	}

	private fun isUserAllowed(tenantId: String?): Boolean {
		return "some-tenant-id" == tenantId
	}

}
// end::snippet[]
