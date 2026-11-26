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

import jakarta.annotation.security.RolesAllowed
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatExceptionOfType
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.access.annotation.Secured
import org.springframework.security.test.context.support.WithMockUser
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit.jupiter.SpringExtension

/**
 * Tests for [EnableReactiveMethodSecurity.jsr250Enabled] and
 * [EnableReactiveMethodSecurity.securedEnabled] with Kotlin coroutines.
 *
 * @author Rohit Behera
 */
@ExtendWith(SpringExtension::class)
@ContextConfiguration
class KotlinReactiveSecuredAndJsr250MethodSecurityTests {

    @Autowired
    lateinit var service: CoroutineService

    @Test
    @WithMockUser(roles = ["ADMIN"])
    fun `suspending RolesAllowed when user has role then success`() {
        runBlocking {
            assertThat(service.suspendingRolesAllowedAdmin()).isEqualTo("admin")
        }
    }

    @Test
    @WithMockUser
    fun `suspending RolesAllowed when user does not have role then denied`() {
        assertThatExceptionOfType(AccessDeniedException::class.java).isThrownBy {
            runBlocking {
                service.suspendingRolesAllowedAdmin()
            }
        }
    }

    @Test
    @WithMockUser(roles = ["ADMIN"])
    fun `flow RolesAllowed when user has role then success`() {
        runBlocking {
            assertThat(service.flowRolesAllowedAdmin().toList()).containsExactly(1, 2)
        }
    }

    @Test
    @WithMockUser
    fun `flow RolesAllowed when user does not have role then denied`() {
        assertThatExceptionOfType(AccessDeniedException::class.java).isThrownBy {
            runBlocking {
                service.flowRolesAllowedAdmin().toList()
            }
        }
    }

    @Test
    @WithMockUser(roles = ["ADMIN"])
    fun `suspending Secured when user has role then success`() {
        runBlocking {
            assertThat(service.suspendingSecuredAdmin()).isEqualTo("admin")
        }
    }

    @Test
    @WithMockUser
    fun `suspending Secured when user does not have role then denied`() {
        assertThatExceptionOfType(AccessDeniedException::class.java).isThrownBy {
            runBlocking {
                service.suspendingSecuredAdmin()
            }
        }
    }

    open class CoroutineService {

        @RolesAllowed("ADMIN")
        open suspend fun suspendingRolesAllowedAdmin(): String = "admin"

        @RolesAllowed("ADMIN")
        open fun flowRolesAllowedAdmin(): Flow<Int> = flowOf(1, 2)

        @Secured("ROLE_ADMIN")
        open suspend fun suspendingSecuredAdmin(): String = "admin"

    }

    @Configuration
    @EnableReactiveMethodSecurity(jsr250Enabled = true, securedEnabled = true)
    open class Config {

        @Bean
        open fun service(): CoroutineService = CoroutineService()

    }

}
