/*
 * Copyright 2002-2018 the original author or authors.
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

package sample.web;

import reactor.core.publisher.Mono;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId;

/**
 * @author Joe Grandja
 * @author Rob Winch
 */
@Controller
@RequestMapping(path = {"/webclient", "/public/webclient"})
public class OAuth2WebClientController {
	private final WebClient webClient;

	public OAuth2WebClientController(WebClient webClient) {
		this.webClient = webClient;
	}

	@GetMapping("/explicit")
	String explicit(Model model) {
		Mono<String> body = this.webClient
				.get()
				.attributes(clientRegistrationId("client-id"))
				.retrieve()
				.bodyToMono(String.class);
		model.addAttribute("body", body);
		return "response";
	}

	@GetMapping("/implicit")
	String implicit(Model model) {
		Mono<String> body = this.webClient
				.get()
				.retrieve()
				.bodyToMono(String.class);
		model.addAttribute("body", body);
		return "response";
	}
}
