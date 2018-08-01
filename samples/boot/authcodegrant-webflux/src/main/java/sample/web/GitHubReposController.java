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

import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.security.Principal;
import java.util.List;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServerOAuth2AuthorizedClientExchangeFilterFunction.oauth2AuthorizedClient;

/**
 * @author Joe Grandja
 * @author Rob Winch
 */
@Controller
public class GitHubReposController {
	private final WebClient webClient;

	public GitHubReposController(WebClient webClient) {
		this.webClient = webClient;
	}

	@GetMapping("/")
	public String index() {
		return "redirect:/repos";
	}

	@GetMapping("/repos")
	public String gitHubRepos(Model model, @RegisteredOAuth2AuthorizedClient("github") OAuth2AuthorizedClient authorizedClient, Principal principal) {
		String endpointUri = "https://api.github.com/user/repos";
		Mono<List> repos = this.webClient
			.get()
			.uri(endpointUri)
			.attributes(oauth2AuthorizedClient(authorizedClient))
			.retrieve()
			.bodyToMono(List.class);
		model.addAttribute("repos", repos);
		model.addAttribute("username", principal.getName());

		return "github-repos";
	}
}
