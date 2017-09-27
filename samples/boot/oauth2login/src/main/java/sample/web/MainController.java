/*
 * Copyright 2012-2017 the original author or authors.
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

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.authentication.OAuth2UserAuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * @author Joe Grandja
 */
@Controller
public class MainController {
	private WebClient webClient = WebClient.create();


	@RequestMapping("/")
	public String index(Model model, @AuthenticationPrincipal OAuth2User user, OAuth2UserAuthenticationToken authentication) {
		model.addAttribute("userName", user.getName());
		model.addAttribute("clientName", authentication.getClientAuthentication().getClientRegistration().getClientName());
		return "index";
	}

	@RequestMapping("/userinfo")
	public String userinfo(Model model, OAuth2UserAuthenticationToken authentication) {
		Map userAttributes = this.webClient
			.filter(oauth2Credentials(authentication))
			.get()
			.uri(authentication.getClientAuthentication().getClientRegistration().getProviderDetails().getUserInfoEndpoint().getUri())
			.retrieve()
			.bodyToMono(Map.class)
			.block();
		model.addAttribute("userAttributes", userAttributes);
		return "userinfo";
	}

	private ExchangeFilterFunction oauth2Credentials(OAuth2UserAuthenticationToken authentication) {
		return ExchangeFilterFunction.ofRequestProcessor(
			clientRequest -> {
				ClientRequest authorizedRequest = ClientRequest.from(clientRequest)
					.header(HttpHeaders.AUTHORIZATION, "Bearer " + authentication.getClientAuthentication().getAccessToken().getTokenValue())
					.build();
				return Mono.just(authorizedRequest);
			});
	}
}
