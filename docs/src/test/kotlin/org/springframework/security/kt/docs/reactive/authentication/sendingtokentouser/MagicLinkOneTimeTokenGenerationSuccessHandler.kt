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

package org.springframework.security.kt.docs.reactive.authentication.sendingtokentouser

import org.springframework.mail.MailSender
import org.springframework.mail.SimpleMailMessage
import org.springframework.security.authentication.ott.OneTimeToken
import org.springframework.security.web.server.authentication.ott.ServerOneTimeTokenGenerationSuccessHandler
import org.springframework.security.web.server.authentication.ott.ServerRedirectOneTimeTokenGenerationSuccessHandler
import org.springframework.stereotype.Component
import org.springframework.stereotype.Controller
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.util.UriComponentsBuilder
import reactor.core.publisher.Mono
import java.util.function.Function


// tag::snippet[]
@Component // <1>
class MagicLinkOneTimeTokenGenerationSuccessHandler(val mailSender: MailSender) : ServerOneTimeTokenGenerationSuccessHandler {

    private val redirectHandler: ServerOneTimeTokenGenerationSuccessHandler = ServerRedirectOneTimeTokenGenerationSuccessHandler("/ott/sent")

    override fun handle(exchange: ServerWebExchange, oneTimeToken: OneTimeToken): Mono<Void> {

        return Mono.just(exchange.request)
            .map(Function { request ->
                UriComponentsBuilder.fromUri(request.uri)
                    .replacePath(request.path.contextPath().value())
                    .replaceQuery(null)
                    .fragment(null)
                    .path("/login/ott")
                    .queryParam("token", oneTimeToken.getTokenValue())
                    .toUriString() // <2>
            })
            .flatMap(Function { uri ->
                val email = getUserEmail(oneTimeToken.getUsername()) // <3>
                val message = SimpleMailMessage()
                message.setTo(email)
                message.subject = "Your Spring Security One Time Token"
                message.text = "Use the following link to sign in into the application: $uri"
                this.mailSender.send(message) // <4>
                Mono.empty()
            })
            .then(this.redirectHandler.handle(exchange, oneTimeToken)) // <5>
    }

    private fun getUserEmail(username: String): String {
        /**/ return username
    }

}

@Controller
class PageController {

    @GetMapping("/ott/sent")
    fun ottSent(): String {
        return "my-template"
    }

}
// end::snippet[]