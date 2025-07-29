/*
 * Copyright 2004-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain clients copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.kt.docs.features.integrations.rest.configurationrestclient

import okhttp3.mockwebserver.MockWebServer
import org.mockito.Mockito
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.kt.docs.features.integrations.rest.clientregistrationid.UserService
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager
import org.springframework.security.oauth2.client.web.client.support.OAuth2RestClientHttpServiceGroupConfigurer
import org.springframework.web.client.RestClient
import org.springframework.web.client.support.RestClientHttpServiceGroupConfigurer
import org.springframework.web.service.registry.HttpServiceGroup
import org.springframework.web.service.registry.HttpServiceGroupConfigurer
import org.springframework.web.service.registry.HttpServiceGroupConfigurer.ClientCallback
import org.springframework.web.service.registry.ImportHttpServices

/**
 * Documentation for [OAuth2RestClientHttpServiceGroupConfigurer].
 * @author Rob Winch
 */
@Configuration(proxyBeanMethods = false)
@ImportHttpServices(types = [UserService::class])
class RestClientHttpInterfaceIntegrationConfiguration {
    // tag::config[]
    @Bean
    fun securityConfigurer(manager: OAuth2AuthorizedClientManager): OAuth2RestClientHttpServiceGroupConfigurer {
        return OAuth2RestClientHttpServiceGroupConfigurer.from(manager)
    }
    // end::config[]

    @Bean
    fun authorizedClientManager(): OAuth2AuthorizedClientManager? {
        return Mockito.mock<OAuth2AuthorizedClientManager?>(OAuth2AuthorizedClientManager::class.java)
    }

    @Bean
    fun groupConfigurer(server: MockWebServer): RestClientHttpServiceGroupConfigurer {
        return RestClientHttpServiceGroupConfigurer { groups: HttpServiceGroupConfigurer.Groups<RestClient.Builder> ->
            groups.forEachClient(ClientCallback { group: HttpServiceGroup, builder: RestClient.Builder ->
                    builder
                        .baseUrl(server.url("").toString())
                })
        }
    }

    @Bean
    fun mockServer(): MockWebServer {
        return MockWebServer()
    }
}
