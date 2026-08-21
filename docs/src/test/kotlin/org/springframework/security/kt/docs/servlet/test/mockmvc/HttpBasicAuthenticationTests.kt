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

package org.springframework.security.kt.docs.servlet.test.mockmvc

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.springframework.http.HttpHeaders
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.setup.MockMvcBuilders
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController

class HttpBasicAuthenticationTests {

    @Test
    fun `http basic`() {
        val mvc = MockMvcBuilders.standaloneSetup(TestController()).build()

        val result =
            // tag::http-basic[]
            mvc.get("/") {
                with(httpBasic("user", "password"))
            }
            // end::http-basic[]
                .andReturn()

        assertThat(result.request.getHeader(HttpHeaders.AUTHORIZATION))
            .isEqualTo("Basic dXNlcjpwYXNzd29yZA==")
    }

    @RestController
    class TestController {

        @GetMapping("/")
        fun index(): String {
            return "ok"
        }

    }

}
