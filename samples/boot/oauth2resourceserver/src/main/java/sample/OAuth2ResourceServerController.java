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
package sample;

import java.security.Principal;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author Josh Cummings
 */
@RestController
public class OAuth2ResourceServerController {

	@GetMapping("/")
	public String index(final Principal principal) {
		return String.format("Hello, %s!", principal.getName());
	}

	@GetMapping("/message")
	public String message() {
		return "secret message";
	}

	@GetMapping("/jwt")
	public String getJwt(@AuthenticationPrincipal final Jwt authenticationPrincipal) {
		return String.format("Hello, %s!", authenticationPrincipal.getSubject());
	}

	@GetMapping("/openid")
	public String getOpenId(@AuthenticationPrincipal final OidcUser authenticationPrincipal) {
		return String.format("Hello, %s!", authenticationPrincipal.getSubject());
	}
}
