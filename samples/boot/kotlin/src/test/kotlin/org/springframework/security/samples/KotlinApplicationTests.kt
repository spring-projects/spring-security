/*
 * Copyright 2002-2019 the original author or authors.
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

import org.assertj.core.api.Assertions.assertThat
import org.junit.Test
import org.junit.runner.RunWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.unauthenticated
import org.springframework.test.context.junit4.SpringRunner
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

@RunWith(SpringRunner::class)
@SpringBootTest
@AutoConfigureMockMvc
class KotlinApplicationTests {

    @Autowired
    private lateinit var mockMvc: MockMvc

    @Test
    fun `index page is not protected`() {
        this.mockMvc.get("/")
                .andExpect {
                    status { isOk() }
                }
    }

    @Test
    fun `protected page redirects to login`() {
        val mvcResult = this.mockMvc.get("/user/index")
                .andExpect { status { is3xxRedirection() } }
                .andReturn()

        assertThat(mvcResult.response.redirectedUrl).endsWith("/log-in")
    }

    @Test
    fun `valid user permitted to log in`() {
        this.mockMvc.perform(formLogin("/log-in").user("user").password("password"))
                .andExpect(authenticated())
    }

    @Test
    fun `invalid user not permitted to log in`() {
        this.mockMvc.perform(formLogin("/log-in").user("invalid").password("invalid"))
                .andExpect(unauthenticated())
                .andExpect(status().is3xxRedirection)
    }

    @Test
    fun `logged in user can access protected page`() {
        val mvcResult = this.mockMvc.perform(formLogin("/log-in").user("user").password("password"))
                .andExpect(authenticated()).andReturn()

        val httpSession = mvcResult.request.getSession(false) as MockHttpSession

        this.mockMvc.get("/user/index") {
            session = httpSession
        }.andExpect {
            status { isOk() }
        }
    }
}
