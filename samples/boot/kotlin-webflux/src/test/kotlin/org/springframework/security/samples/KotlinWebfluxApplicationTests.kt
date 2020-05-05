/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.samples

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.ApplicationContext
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.security.test.context.support.WithMockUser

@SpringBootTest
class KotlinWebfluxApplicationTests {

    lateinit var rest: WebTestClient

    @Autowired
    fun setup(context: ApplicationContext) {
        rest = WebTestClient
                .bindToApplicationContext(context)
                .configureClient()
                .build()
    }

    @Test
    fun `index page is not protected`() {
        rest
                .get()
                .uri("/")
                .exchange()
                .expectStatus().isOk
    }

    @Test
    fun `protected page when unauthenticated then redirects to login `() {
        rest
                .get()
                .uri("/user/index")
                .exchange()
                .expectStatus().is3xxRedirection
                .expectHeader().valueEquals("Location", "/log-in")
    }

    @Test
    @WithMockUser
    fun `protected page can be accessed when authenticated`() {
        rest
                .get()
                .uri("/user/index")
                .exchange()
                .expectStatus().isOk
    }
}
