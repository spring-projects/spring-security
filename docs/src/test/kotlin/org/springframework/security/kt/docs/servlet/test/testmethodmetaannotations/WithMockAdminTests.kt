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

package org.springframework.security.kt.docs.servlet.test.testmethodmetaannotations

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.core.MessageService
import org.springframework.security.kt.docs.servlet.test.testmethod.HelloMessageService
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit.jupiter.SpringExtension

@ExtendWith(SpringExtension::class)
@ContextConfiguration
class WithMockAdminTests {

    @Autowired
    lateinit var messageService: MessageService

    @Test
    @WithMockAdmin
    fun getMessageWithMockUserAdminRoles() {
        val message = messageService.message
        assertThat(message)
            .contains("rob")
            .contains("ROLE_ADMIN")
            .contains("ROLE_USER")
    }

    @EnableMethodSecurity
    @Configuration
    open class Config {
        @Bean
        open fun messageService(): MessageService {
            return HelloMessageService()
        }
    }
}
