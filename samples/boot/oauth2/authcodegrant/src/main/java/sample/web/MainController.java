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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.ClientAuthorizationRequiredException;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * @author Joe Grandja
 */
@Controller
public class MainController {
	@Autowired
	private OAuth2AuthorizedClientService authorizedClientService;

	@GetMapping("/")
	public String index() {
		return "redirect:/repos";
	}

	@GetMapping("/repos")
	public String gitHubRepos(Model model, Authentication authentication) {
		String registrationId = "github";

		OAuth2AuthorizedClient authorizedClient =
			this.authorizedClientService.loadAuthorizedClient(
				registrationId, authentication.getName());
		if (authorizedClient == null) {
			throw new ClientAuthorizationRequiredException(registrationId);
		}

		String endpointUri = "https://api.github.com/user/repos";
		List repos = WebClient.builder()
			.filter(oauth2Credentials(authorizedClient))
			.build()
			.get()
			.uri(endpointUri)
			.retrieve()
			.bodyToMono(List.class)
			.block();
		model.addAttribute("repos", repos);

		return "github-repos";
	}

	private ExchangeFilterFunction oauth2Credentials(OAuth2AuthorizedClient authorizedClient) {
		return ExchangeFilterFunction.ofRequestProcessor(
			clientRequest -> {
				ClientRequest authorizedRequest = ClientRequest.from(clientRequest)
					.header(HttpHeaders.AUTHORIZATION, "Bearer " + authorizedClient.getAccessToken().getTokenValue())
					.build();
				return Mono.just(authorizedRequest);
			});
	}
}
