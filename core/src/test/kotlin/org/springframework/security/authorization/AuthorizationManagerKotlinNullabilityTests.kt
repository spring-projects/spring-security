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

package org.springframework.security.authorization

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.security.authentication.TestingAuthenticationToken
import org.springframework.security.core.Authentication

class AuthorizationManagerKotlinNullabilityTests {

    private val authentication: Authentication = TestingAuthenticationToken("user", "password", "ROLE_ADMIN")

    @Test
    fun `authority authorization manager allows nullable object type`() {
        val manager: AuthorizationManager<Any?> = AuthorityAuthorizationManager.hasRole("ADMIN")

        assertThat(manager.authorize({ authentication }, null)!!.isGranted).isTrue()
    }

    @Test
    fun `authenticated authorization manager allows nullable object type`() {
        val manager: AuthorizationManager<Any?> = AuthenticatedAuthorizationManager.authenticated()

        assertThat(manager.authorize({ authentication }, null)!!.isGranted).isTrue()
    }

    @Test
    fun `single result authorization manager allows nullable object type`() {
        val manager: AuthorizationManager<Any?> = SingleResultAuthorizationManager.permitAll()

        assertThat(manager.authorize({ authentication }, null)!!.isGranted).isTrue()
    }

    @Test
    fun `all authorities authorization manager allows nullable object type`() {
        val manager: AuthorizationManager<Any?> = AllAuthoritiesAuthorizationManager.hasAllRoles("ADMIN")

        assertThat(manager.authorize({ authentication }, null)!!.isGranted).isTrue()
    }

    @Test
    fun `required authorities authorization manager allows nullable object type`() {
        val manager: AuthorizationManager<Any?> = RequiredAuthoritiesAuthorizationManager { listOf("ROLE_ADMIN") }

        assertThat(manager.authorize({ authentication }, null)!!.isGranted).isTrue()
    }

    @Test
    fun `all required factors authorization manager allows nullable object type`() {
        val manager: AuthorizationManager<Any?> = AllRequiredFactorsAuthorizationManager.builder<Any?>()
            .requireFactor { it.passwordAuthority() }
            .build()

        assertThat(manager.authorize({ authentication }, null)!!.isGranted).isFalse()
    }

    @Test
    fun `conditional authorization manager allows nullable object type`() {
        val manager: AuthorizationManager<Any?> = ConditionalAuthorizationManager.`when`<Any?> { true }
            .whenTrue(SingleResultAuthorizationManager.permitAll<Any?>())
            .build()

        assertThat(manager.authorize({ authentication }, null)!!.isGranted).isTrue()
    }

    @Test
    fun `authorization manager compositions allow nullable object type`() {
        val manager: AuthorizationManager<Any?> = AuthorizationManagers.anyOf(
            SingleResultAuthorizationManager.denyAll(),
            SingleResultAuthorizationManager.permitAll(),
        )

        assertThat(manager.authorize({ authentication }, null)!!.isGranted).isTrue()
    }

}
