/*
 * Copyright 2002-2018 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package sample.web;

import static org.springframework.security.oauth2.client.web.reactive.function.client.OAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

import java.util.Map;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.OAuth2Client;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.client.WebClient;

import reactor.core.publisher.Mono;

/**
 * @author Rob Winch
 */
@Controller
public class OAuth2LoginController {
	private final WebClient webClient;

	public OAuth2LoginController(WebClient webClient) {
		this.webClient = webClient;
	}

	@GetMapping("/")
	public String index(Model model, @OAuth2Client OAuth2AuthorizedClient authorizedClient) {
		model.addAttribute("userName", authorizedClient.getPrincipalName());
		model.addAttribute("clientName", authorizedClient.getClientRegistration().getClientName());
		return "index";
	}

	@GetMapping("/userinfo")
	public String userinfo(Model model, @OAuth2Client OAuth2AuthorizedClient authorizedClient) {
		Mono<Map> userAttributes = Mono.empty();
		String userInfoEndpointUri = authorizedClient.getClientRegistration()
			.getProviderDetails().getUserInfoEndpoint().getUri();
		if (!StringUtils.isEmpty(userInfoEndpointUri)) {	// userInfoEndpointUri is optional for OIDC Clients
			userAttributes = this.webClient
				.get()
				.uri(userInfoEndpointUri)
				.attributes(oauth2AuthorizedClient(authorizedClient))
				.retrieve()
				.bodyToMono(Map.class);
		}
		model.addAttribute("userAttributes", userAttributes);
		return "userinfo";
	}
}
