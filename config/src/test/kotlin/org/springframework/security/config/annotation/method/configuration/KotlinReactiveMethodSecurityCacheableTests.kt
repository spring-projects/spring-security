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

package org.springframework.security.config.annotation.method.configuration

import kotlinx.coroutines.runBlocking
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.cache.CacheManager
import org.springframework.cache.annotation.Cacheable
import org.springframework.cache.annotation.EnableCaching
import org.springframework.cache.concurrent.ConcurrentMapCacheManager
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.access.prepost.PreAuthorize
import org.springframework.security.test.context.support.WithMockUser
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit.jupiter.SpringExtension
import java.util.concurrent.atomic.AtomicInteger

// gh-19400
@ExtendWith(SpringExtension::class)
@ContextConfiguration
class KotlinReactiveMethodSecurityCacheableTests {

    @Autowired
    lateinit var cachedService: CachedSuspendService

    @Autowired
    lateinit var cacheManager: CacheManager

    @BeforeEach
    fun setUp() {
        cacheManager.getCache("demo")?.clear()
        cachedService.resetCounter()
    }

    @Test
    @WithMockUser(authorities = ["demo.read"])
    fun `suspending PreAuthorize and Cacheable when cache hit then returns cached value`() {
        runBlocking {
            val first = cachedService.demo()
            val second = cachedService.demo()
            assertThat(first).isEqualTo(second)
            assertThat(first.invocation).isEqualTo(1)
            assertThat(cachedService.invocationCount()).isEqualTo(1)
        }
    }

    @Test
    @WithMockUser(authorities = ["demo.read"])
    fun `suspending PreAuthorize and Cacheable when cache miss then invokes target`() {
        runBlocking {
            val result = cachedService.demo()
            assertThat(result.invocation).isEqualTo(1)
            assertThat(result.message).isEqualTo("cached response")
            assertThat(cachedService.invocationCount()).isEqualTo(1)
        }
    }

    @Configuration
    @EnableReactiveMethodSecurity
    @EnableCaching
    open class Config {
        @Bean
        open fun cacheManager(): CacheManager = ConcurrentMapCacheManager("demo")

        @Bean
        open fun cachedService(): CachedSuspendService = CachedSuspendService()
    }
}

open class CachedSuspendService {
    private val invocationCounter = AtomicInteger()

    @Cacheable("demo", key = "'fixed'")
    @PreAuthorize("hasAuthority('demo.read')")
    open suspend fun demo(): DemoResponse =
        DemoResponse(
            message = "cached response",
            invocation = invocationCounter.incrementAndGet(),
        )

    open fun invocationCount(): Int = invocationCounter.get()

    open fun resetCounter() {
        invocationCounter.set(0)
    }
}

data class DemoResponse(
    val message: String,
    val invocation: Int,
)
