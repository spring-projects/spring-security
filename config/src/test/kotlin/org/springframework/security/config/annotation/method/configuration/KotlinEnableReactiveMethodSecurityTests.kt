/*
 * Copyright 2002-2021 the original author or authors.
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

import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.runBlocking
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatExceptionOfType
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.access.AccessDeniedException
import org.springframework.security.test.context.support.WithMockUser
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit4.SpringRunner

@RunWith(SpringRunner::class)
@ContextConfiguration
class KotlinEnableReactiveMethodSecurityTests {

    @Autowired
    var messageService: KotlinReactiveMessageService? = null

    @Test
    fun suspendingGetResultWhenPermitAllThenSuccess() {
        runBlocking {
            assertThat(messageService!!.suspendingNoAuth()).isEqualTo("success")
        }
    }

    @Test
    @WithMockUser(authorities = ["ROLE_ADMIN"])
    fun suspendingPreAuthorizeHasRoleWhenGrantedThenSuccess() {
        runBlocking {
            assertThat(messageService!!.suspendingPreAuthorizeHasRole()).isEqualTo("admin")
        }
    }

    @Test
    fun suspendingPreAuthorizeHasRoleWhenNoAuthenticationThenDenied() {
        assertThatExceptionOfType(AccessDeniedException::class.java).isThrownBy {
            runBlocking {
                messageService!!.suspendingPreAuthorizeHasRole()
            }
        }
    }

    @Test
    @WithMockUser
    fun suspendingPreAuthorizeBeanWhenGrantedThenSuccess() {
        runBlocking {
            assertThat(messageService!!.suspendingPreAuthorizeBean(true)).isEqualTo("check")
        }
    }

    @Test
    fun suspendingPreAuthorizeBeanWhenNotAuthorizedThenDenied() {
        assertThatExceptionOfType(AccessDeniedException::class.java).isThrownBy {
            runBlocking {
                messageService!!.suspendingPreAuthorizeBean(false)
            }
        }
    }

    @Test
    @WithMockUser("user")
    fun suspendingPostAuthorizeWhenAuthorizedThenSuccess() {
        runBlocking {
            assertThat(messageService!!.suspendingPostAuthorizeContainsName()).isEqualTo("user")
        }
    }

    @Test
    @WithMockUser("other-user")
    fun suspendingPostAuthorizeWhenNotAuthorizedThenDenied() {
        assertThatExceptionOfType(AccessDeniedException::class.java).isThrownBy {
            runBlocking {
                messageService!!.suspendingPostAuthorizeContainsName()
            }
        }
    }

    @Test
    @WithMockUser(authorities = ["ROLE_ADMIN"])
    fun suspendingFlowPreAuthorizeHasRoleWhenGrantedThenSuccess() {
        runBlocking {
            assertThat(messageService!!.suspendingFlowPreAuthorize().toList()).containsExactly(1, 2, 3)
        }
    }

    @Test
    fun suspendingFlowPreAuthorizeHasRoleWhenNoAuthenticationThenDenied() {
        assertThatExceptionOfType(AccessDeniedException::class.java).isThrownBy {
            runBlocking {
                messageService!!.suspendingFlowPreAuthorize().collect()
            }
        }
    }

    @Test
    fun suspendingFlowPostAuthorizeWhenAuthorizedThenSuccess() {
        runBlocking {
            assertThat(messageService!!.suspendingFlowPostAuthorize(true).toList()).containsExactly(1, 2, 3)
        }
    }

    @Test
    fun suspendingFlowPostAuthorizeWhenNotAuthorizedThenDenied() {
        assertThatExceptionOfType(AccessDeniedException::class.java).isThrownBy {
            runBlocking {
                messageService!!.suspendingFlowPostAuthorize(false).collect()
            }
        }
    }

    @Test
    @WithMockUser(authorities = ["ROLE_ADMIN"])
    fun flowPreAuthorizeHasRoleWhenGrantedThenSuccess() {
        runBlocking {
            assertThat(messageService!!.flowPreAuthorize().toList()).containsExactly(1, 2, 3)
        }
    }

    @Test
    fun flowPreAuthorizeHasRoleWhenNoAuthenticationThenDenied() {
        assertThatExceptionOfType(AccessDeniedException::class.java).isThrownBy {
            runBlocking {
                messageService!!.flowPreAuthorize().collect()
            }
        }
    }

    @Test
    fun flowPostAuthorizeWhenAuthorizedThenSuccess() {
        runBlocking {
            assertThat(messageService!!.flowPostAuthorize(true).toList()).containsExactly(1, 2, 3)
        }
    }

    @Test
    fun flowPostAuthorizeWhenNotAuthorizedThenDenied() {
        assertThatExceptionOfType(AccessDeniedException::class.java).isThrownBy {
            runBlocking {
                messageService!!.flowPostAuthorize(false).collect()
            }
        }
    }

    @EnableReactiveMethodSecurity
    @Configuration
    open class Config {

        @Bean
        open fun messageService(): KotlinReactiveMessageServiceImpl {
            return KotlinReactiveMessageServiceImpl()
        }

        @Bean
        open fun authz(): Authz {
            return Authz()
        }

        open class Authz {
            fun check(r: Boolean): Boolean {
                return r
            }
        }
    }
}
