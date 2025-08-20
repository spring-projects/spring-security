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
package org.springframework.security.kt.docs.reactive.configuration.dslbeanordering

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.kt.docs.servlet.configuration.customizerbeanordering.CustomizerBeanOrderingConfiguration
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.mockUser
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

/**
 *
 */
@ExtendWith(SpringTestContextExtension::class)
class DslBeanOrderingTests {
    @JvmField
    val spring = SpringTestContext(this).mockMvcAfterSpringSecurityOk()

    @Autowired
    lateinit var webTest: WebTestClient

    @Test
    fun dslOrdered() {
        this.spring.register(org.springframework.security.kt.docs.reactive.configuration.customizerbeanordering.CustomizerBeanOrderingConfiguration::class.java).autowire()
        // @formatter:off
        this.webTest.mutateWith(mockUser("admin").roles("ADMIN"))
            .get()
            .uri("https://localhost/admins/1")
            .exchange()
            .expectStatus().isOk
        this.webTest.mutateWith(mockUser("user").roles("USER"))
            .get()
            .uri("https://localhost/admins/1")
            .exchange()
            .expectStatus().isForbidden
        this.webTest.mutateWith(mockUser("user").roles("USER"))
            .get()
            .uri("https://localhost/users/1")
            .exchange()
            .expectStatus().isOk
        this.webTest.mutateWith(mockUser("user").roles("OTHER"))
            .get()
            .uri("https://localhost/users/1")
            .exchange()
            .expectStatus().isForbidden
        this.webTest.mutateWith(mockUser("other").roles("OTHER"))
            .get()
            .uri("https://localhost/other")
            .exchange()
            .expectStatus().isOk
        // @formatter:on
    }
}
