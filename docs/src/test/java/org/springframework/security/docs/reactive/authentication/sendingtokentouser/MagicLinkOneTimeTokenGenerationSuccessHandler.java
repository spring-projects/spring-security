/*
 * Copyright 2004-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	  https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.docs.reactive.authentication.sendingtokentouser;

import org.springframework.mail.MailSender;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.web.server.authentication.ott.ServerOneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.server.authentication.ott.ServerRedirectOneTimeTokenGenerationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;

// tag::snippet[]
@Component // <1>
public class MagicLinkOneTimeTokenGenerationSuccessHandler implements ServerOneTimeTokenGenerationSuccessHandler {

	private final MailSender mailSender;

	private final ServerOneTimeTokenGenerationSuccessHandler redirectHandler = new ServerRedirectOneTimeTokenGenerationSuccessHandler("/ott/sent");

	public MagicLinkOneTimeTokenGenerationSuccessHandler(MailSender mailSender) {
		this.mailSender = mailSender;
	}

	@Override
	public Mono<Void> handle(ServerWebExchange exchange, OneTimeToken oneTimeToken) {

		return Mono.just(exchange.getRequest())
			.map((request) ->
				UriComponentsBuilder.fromUri(request.getURI())
					.replacePath(request.getPath().contextPath().value())
					.replaceQuery(null)
					.fragment(null)
					.path("/login/ott")
					.queryParam("token", oneTimeToken.getTokenValue())
					.toUriString() // <2>
			)
			.flatMap((uri) -> {

				String email = getUserEmail(oneTimeToken.getUsername()); // <3>
				SimpleMailMessage message = new SimpleMailMessage();
				message.setTo(email);
				message.setSubject("Your Spring Security One Time Token");
				message.setText("Use the following link to sign in into the application: " + uri);
				this.mailSender.send(message); // <4>
				return Mono.empty();
			})
			.then(this.redirectHandler.handle(exchange, oneTimeToken)); // <5>
	}

	private String getUserEmail(String username) {
		/**/ return username;
	}

}

@Controller
class PageController {

	@GetMapping("/ott/sent")
	String ottSent() {
		return "my-template";
	}

}
// end::snippet[]