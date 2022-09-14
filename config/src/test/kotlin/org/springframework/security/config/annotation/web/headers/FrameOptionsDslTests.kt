/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.annotation.web.headers

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

/**
 * Tests for [FrameOptionsDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class FrameOptionsDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `headers when frame options configured then frame options deny header`() {
        this.spring.register(FrameOptionsConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header { string(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS, XFrameOptionsHeaderWriter.XFrameOptionsMode.DENY.name) }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class FrameOptionsConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    defaultsDisabled = true
                    frameOptions { }
                }
            }
            return http.build()
        }
    }

    @Test
    fun `headers when frame options deny configured then frame options deny header`() {
        this.spring.register(FrameOptionsDenyConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header { string(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS, XFrameOptionsHeaderWriter.XFrameOptionsMode.DENY.name) }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class FrameOptionsDenyConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    defaultsDisabled = true
                    frameOptions {
                        deny = true
                    }
                }
            }
            return http.build()
        }
    }

    @Test
    fun `headers when frame options same origin configured then frame options same origin header`() {
        this.spring.register(FrameOptionsSameOriginConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header { string(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS, XFrameOptionsHeaderWriter.XFrameOptionsMode.SAMEORIGIN.name) }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class FrameOptionsSameOriginConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    defaultsDisabled = true
                    frameOptions {
                        sameOrigin = true
                    }
                }
            }
            return http.build()
        }
    }

    @Test
    fun `headers when frame options same origin and deny configured then frame options deny header`() {
        this.spring.register(FrameOptionsSameOriginAndDenyConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header { string(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS, XFrameOptionsHeaderWriter.XFrameOptionsMode.DENY.name) }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class FrameOptionsSameOriginAndDenyConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    defaultsDisabled = true
                    frameOptions {
                        sameOrigin = true
                        deny = true
                    }
                }
            }
            return http.build()
        }
    }

    @Test
    fun `headers when frame options disabled then no frame options header in response`() {
        this.spring.register(FrameOptionsDisabledConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header { doesNotExist(XFrameOptionsServerHttpHeadersWriter.X_FRAME_OPTIONS) }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class FrameOptionsDisabledConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                headers {
                    frameOptions {
                        disable()
                    }
                }
            }
            return http.build()
        }
    }
}
