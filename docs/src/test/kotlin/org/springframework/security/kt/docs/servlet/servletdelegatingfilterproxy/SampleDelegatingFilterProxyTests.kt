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

package org.springframework.security.kt.docs.servlet.servletdelegatingfilterproxy

import jakarta.servlet.Filter
import jakarta.servlet.FilterChain
import jakarta.servlet.FilterConfig
import jakarta.servlet.ServletContext
import jakarta.servlet.ServletException
import jakarta.servlet.ServletRequest
import jakarta.servlet.ServletResponse
import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.web.servlet.MockServletContext
import org.springframework.util.Assert
import org.springframework.web.context.WebApplicationContext
import org.springframework.web.context.support.StaticWebApplicationContext
import java.io.IOException
import org.assertj.core.api.Assertions.assertThat
import java.util.Enumeration
import java.util.Collections
import kotlin.collections.LinkedHashMap

class SampleDelegatingFilterProxyTests {

	@Test
	@Throws(ServletException::class, IOException::class)
	fun testFilter() {
		val sc: ServletContext = MockServletContext()
		val wac = StaticWebApplicationContext()
		wac.registerSingleton("targetFilter", MockFilter::class.java)
		wac.setServletContext(sc)
		wac.refresh()
		sc.setAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, wac)

		val targetFilter = wac.getBean("targetFilter") as MockFilter
		val proxyConfig = MockFilterConfig(sc)
		proxyConfig.addInitParameter("targetBeanName", "targetFilter")
		val filterProxy = SampleDelegatingFilterProxy("targetFilter", wac)
		filterProxy.init(proxyConfig)

		val request = MockHttpServletRequest()
		val response = MockHttpServletResponse()
		filterProxy.doFilter(request, response, null)

		assertThat(targetFilter.filterConfig).isNull()
		assertThat(request.getAttribute("called")).isEqualTo(true)

		filterProxy.destroy()
		assertThat(targetFilter.filterConfig).isNull()
	}

	private class MockFilter : Filter {
		var filterConfig: FilterConfig? = null

		@Throws(ServletException::class)
		override fun init(filterConfig: FilterConfig) {
			this.filterConfig = filterConfig
		}

		@Throws(IOException::class, ServletException::class)
		override fun doFilter(request: ServletRequest, response: ServletResponse, chain: FilterChain?) {
			request.setAttribute("called", true)
		}

		override fun destroy() {
			filterConfig = null
		}
	}

	private class MockFilterConfig(
			private val servletContext: ServletContext
	) : FilterConfig {
		private val filterName: String = ""
		private val initParameters = LinkedHashMap<String, String>()

		override fun getFilterName(): String = filterName

		override fun getServletContext(): ServletContext = servletContext

		fun addInitParameter(name: String, value: String) {
			Assert.notNull(name, "Parameter name must not be null")
			initParameters[name] = value
		}

		override fun getInitParameter(name: String): String? {
				Assert.notNull(name, "Parameter name must not be null")
		return initParameters[name]
        }

		override fun getInitParameterNames(): Enumeration<String> =
		Collections.enumeration(initParameters.keys)
	}
}
