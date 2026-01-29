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
package org.springframework.security.kt.docs.reactive.authentication.reactivex509

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.core.io.ClassPathResource
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder.Http200RestController
import org.springframework.security.web.authentication.preauth.x509.X509TestUtils
import org.springframework.test.web.reactive.server.UserWebTestClientConfigurer.x509
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.server.WebFilter
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * Tests [CustomX509Configuration].
 *
 * @author Rob Winch
 */
@ExtendWith(SpringTestContextExtension::class)
class X509ConfigurationTests {
    @JvmField
    val spring: SpringTestContext = SpringTestContext(this)

    var client: WebTestClient? = null

    @Autowired
    fun setSpringSecurityFilterChain(springSecurityFilterChain: WebFilter) {
        this.client = WebTestClient
            .bindToController(Http200RestController::class.java)
            .webFilter<WebTestClient.ControllerSpec>(springSecurityFilterChain)
            .apply<WebTestClient.ControllerSpec>(SecurityMockServerConfigurers.springSecurity())
            .configureClient()
            .build()
    }

    @Test
    fun x509WhenDefaultX509Configuration() {
        this.spring.register(DefaultX509Configuration::class.java).autowire()
        val certificate = loadCert<X509Certificate>("rod.cer")
        // @formatter:off
        this.client!!.mutateWith(x509(certificate))
            .get()
            .uri("/")
            .exchange()
            .expectStatus().isOk()
        // @formatter:on
    }

    @Test
    fun x509WhenCustomX509Configuration() {
        this.spring.register(CustomX509Configuration::class.java).autowire()
        val certificate = X509TestUtils.buildTestCertificate()
        // @formatter:off
        this.client!!.mutateWith(x509(certificate))
            .get()
            .uri("/")
            .exchange()
            .expectStatus().isOk()
        // @formatter:on
    }

    @Suppress("UNCHECKED_CAST")
    private fun <T : Certificate?> loadCert(location: String): T {
        try {
            ClassPathResource(location).inputStream.use { `is` ->
                val certFactory = CertificateFactory.getInstance("X.509")
                return certFactory.generateCertificate(`is`) as T
            }
        } catch (ex: Exception) {
            throw IllegalArgumentException(ex)
        }
    }
}
