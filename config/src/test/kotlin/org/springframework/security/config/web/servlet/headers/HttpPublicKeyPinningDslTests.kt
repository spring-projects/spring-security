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

package org.springframework.security.config.web.servlet.headers

import org.assertj.core.api.Assertions
import org.junit.Rule
import org.junit.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.test.SpringTestRule
import org.springframework.security.config.web.servlet.invoke
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get

/**
 * Tests for [HttpPublicKeyPinningDsl]
 *
 * @author Eleftheria Stein
 */
class HttpPublicKeyPinningDslTests {
    @Rule
    @JvmField
    var spring = SpringTestRule()

    @Autowired
    lateinit var mockMvc: MockMvc

    private val HPKP_RO_HEADER_NAME = "Public-Key-Pins-Report-Only"
    private val HPKP_HEADER_NAME = "Public-Key-Pins"

    @Test
    fun `headers when HPKP configured and no pin then no headers in response`() {
        this.spring.register(HpkpNoPinConfig::class.java).autowire()

        val result = this.mockMvc.get("/") {
            secure = true
        }.andReturn()

        Assertions.assertThat(result.response.headerNames).isEmpty()
    }

    @EnableWebSecurity
    open class HpkpNoPinConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                headers {
                    defaultsDisabled = true
                    httpPublicKeyPinning { }
                }
            }
        }
    }

    @Test
    fun `headers when HPKP configured with pin then header in response`() {
        this.spring.register(HpkpPinConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header { string(HPKP_RO_HEADER_NAME, "max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\"") }
        }
    }

    @EnableWebSecurity
    open class HpkpPinConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                headers {
                    defaultsDisabled = true
                    httpPublicKeyPinning {
                        pins = mapOf(Pair("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=", "sha256"))
                    }
                }
            }
        }
    }

    @Test
    fun `headers when HPKP configured with maximum age then maximum age in header`() {
        this.spring.register(HpkpMaxAgeConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header { string(HPKP_RO_HEADER_NAME, "max-age=604800 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\"") }
        }
    }

    @EnableWebSecurity
    open class HpkpMaxAgeConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                headers {
                    defaultsDisabled = true
                    httpPublicKeyPinning {
                        pins = mapOf(Pair("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=", "sha256"))
                        maxAgeInSeconds = 604800
                    }
                }
            }
        }
    }

    @Test
    fun `headers when HPKP configured with report only false then public key pins header in response`() {
        this.spring.register(HpkpReportOnlyFalseConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header { string(HPKP_HEADER_NAME, "max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\"") }
        }
    }

    @EnableWebSecurity
    open class HpkpReportOnlyFalseConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                headers {
                    defaultsDisabled = true
                    httpPublicKeyPinning {
                        pins = mapOf(Pair("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=", "sha256"))
                        reportOnly = false
                    }
                }
            }
        }
    }

    @Test
    fun `headers when HPKP configured with include subdomains then include subdomains in header`() {
        this.spring.register(HpkpIncludeSubdomainsConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header {
                string(HPKP_RO_HEADER_NAME,
                        "max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\" ; includeSubDomains")
            }
        }
    }

    @EnableWebSecurity
    open class HpkpIncludeSubdomainsConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                headers {
                    defaultsDisabled = true
                    httpPublicKeyPinning {
                        pins = mapOf(Pair("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=", "sha256"))
                        includeSubDomains = true
                    }
                }
            }
        }
    }

    @Test
    fun `headers when HPKP configured with report uri then report uri in header`() {
        this.spring.register(HpkpReportUriConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header {
                string(HPKP_RO_HEADER_NAME,
                        "max-age=5184000 ; pin-sha256=\"d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=\" ; report-uri=\"https://example.com\"")
            }
        }
    }

    @EnableWebSecurity
    open class HpkpReportUriConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                headers {
                    defaultsDisabled = true
                    httpPublicKeyPinning {
                        pins = mapOf(Pair("d6qzRu9zOECb90Uez27xWltNsj0e1Md7GkYYkVoZWmM=", "sha256"))
                        reportUri = "https://example.com"
                    }
                }
            }
        }
    }

    @Test
    fun `headers when HPKP disabled then no HPKP header in response`() {
        this.spring.register(HpkpDisabledConfig::class.java).autowire()

        this.mockMvc.get("/") {
            secure = true
        }.andExpect {
            header {
                doesNotExist(HPKP_RO_HEADER_NAME)
            }
        }
    }

    @EnableWebSecurity
    open class HpkpDisabledConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                headers {
                    httpPublicKeyPinning {
                        disable()
                    }
                }
            }
        }
    }
}
