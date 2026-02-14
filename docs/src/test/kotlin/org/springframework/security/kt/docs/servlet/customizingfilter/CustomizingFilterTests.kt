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

package org.springframework.security.kt.docs.servlet.customizingfilter

import jakarta.servlet.Filter
import jakarta.servlet.FilterChain
import jakarta.servlet.ServletRequest
import jakarta.servlet.ServletResponse
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpHeaders
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

/**
 * Tests for customizing security filters.
 *
 */
@ExtendWith(SpringTestContextExtension::class)
class CustomizingFilterTests {

	@JvmField
	val spring = SpringTestContext(this)

	@Autowired
	lateinit var mvc: MockMvc

	@Autowired
	lateinit var filterChainProxy: FilterChainProxy

	@Test
	fun `filter chain when basic default then BasicAuthenticationFilter present`() {
		spring.register(SecurityConfigBasicDefault::class.java).autowire()
		val filters = filterChainProxy.getFilters("/")
		assertThat(filters).extracting("class").contains(BasicAuthenticationFilter::class.java)
	}

	@Test
	fun `filter chain when custom filter then custom filter present`() {
		spring.register(SecurityConfigCustom::class.java).autowire()
		val filters = filterChainProxy.getFilters("/")
		assertThat(filters).extracting("class").contains(SecurityConfigCustom.MyBasicAuthenticationFilter::class.java)
		assertThat(filters).extracting("class").doesNotContain(BasicAuthenticationFilter::class.java)
	}

	@Test
	fun `filter chain when incorrect then both filters present`() {
		spring.register(SecurityConfigIncorrect::class.java).autowire()
		val filters = filterChainProxy.getFilters("/")
		assertThat(filters).extracting("class").contains(BasicAuthenticationFilter::class.java)
		assertThat(filters).extracting("class").contains(SecurityConfigIncorrect.MyBasicAuthenticationFilter::class.java)
	}

	@Configuration
	@EnableWebSecurity
	open class SecurityConfigBasicDefault {

		// tag::basic-default[]
		@Bean
		open fun filterChain(http: HttpSecurity): SecurityFilterChain {
			http {
				httpBasic { }
				// ...
			}
			return http.build()
		}
		// end::basic-default[]

	}

	@Configuration
	@EnableWebSecurity
	open class SecurityConfigCustom {

		// tag::custom-filter[]
		@Bean
		open fun filterChain(http: HttpSecurity): SecurityFilterChain {
			val basic = MyBasicAuthenticationFilter()
			// ... configure

			http
				// ...
				.addFilterAt(basic, BasicAuthenticationFilter::class.java)

			return http.build()
		}
		// end::custom-filter[]

		class MyBasicAuthenticationFilter : Filter {
			override fun doFilter(request: ServletRequest, response: ServletResponse, chain: FilterChain) {
				chain.doFilter(request, response)
			}
		}

	}

	@Configuration
	@EnableWebSecurity
	open class SecurityConfigIncorrect {

		// tag::incorrect[]
		@Bean
		open fun filterChain(http: HttpSecurity): SecurityFilterChain {
			val basic = MyBasicAuthenticationFilter()
			// ... configure

			http {
				httpBasic { }
			}

			// ... on no! BasicAuthenticationFilter is added twice!
			http.addFilterAt(basic, BasicAuthenticationFilter::class.java)

			return http.build()
		}
		// end::incorrect[]

		class MyBasicAuthenticationFilter : Filter {
			override fun doFilter(request: ServletRequest, response: ServletResponse, chain: FilterChain) {
				chain.doFilter(request, response)
			}
		}

	}

}
