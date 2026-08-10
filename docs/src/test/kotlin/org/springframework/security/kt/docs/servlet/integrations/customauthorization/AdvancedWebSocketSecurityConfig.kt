/*
 * Copyright 2026-present the original author or authors.
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

package org.springframework.security.kt.docs.servlet.integrations.customauthorization

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.messaging.Message
import org.springframework.security.authorization.AuthorizationManager
import org.springframework.security.messaging.access.intercept.MessageMatcherDelegatingAuthorizationManager

import org.springframework.messaging.simp.SimpMessageType.MESSAGE
import org.springframework.messaging.simp.SimpMessageType.SUBSCRIBE

// tag::snippet[]
@Configuration
open class AdvancedWebSocketSecurityConfig {

    @Bean
    open fun messageAuthorizationManager(messages: MessageMatcherDelegatingAuthorizationManager.Builder): AuthorizationManager<Message<*>> {
        messages
            .nullDestMatcher().authenticated() // <1>
            .simpSubscribeDestMatchers("/user/queue/errors").permitAll() // <2>
            .simpDestMatchers("/app/**").hasRole("USER") // <3>
            .simpSubscribeDestMatchers("/user/**", "/topic/friends/*").hasRole("USER") // <4>
            .simpTypeMatchers(MESSAGE, SUBSCRIBE).denyAll() // <5>
            .anyMessage().denyAll() // <6>

        return messages.build()
    }

}
// end::snippet[]