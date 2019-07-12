/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.webauthn;

import com.webauthn4j.util.Base64UrlUtil;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.webauthn.challenge.WebAuthnChallengeRepository;
import org.springframework.security.webauthn.userdetails.WebAuthnUserDetails;
import org.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;

import javax.servlet.http.HttpServletRequest;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

public class WebAuthnOptionWebHelper {

	private WebAuthnChallengeRepository challengeRepository;
	private WebAuthnUserDetailsService userDetailsService;

	public WebAuthnOptionWebHelper(WebAuthnChallengeRepository challengeRepository, WebAuthnUserDetailsService userDetailsService) {
		this.challengeRepository = challengeRepository;
		this.userDetailsService = userDetailsService;
	}

	public String getChallenge(HttpServletRequest request) {
		return Base64UrlUtil.encodeToString(challengeRepository.loadOrGenerateChallenge(request).getValue());
	}

	public List<String> getCredentialIds() {
		String username = SecurityContextHolder.getContext().getAuthentication().getName();
		if (username == null) {
			return Collections.emptyList();
		} else {
			try {
				WebAuthnUserDetails webAuthnUserDetails = userDetailsService.loadWebAuthnUserByUsername(username);
				return webAuthnUserDetails.getAuthenticators().stream()
						.map(authenticator -> Base64UrlUtil.encodeToString(authenticator.getCredentialId()))
						.collect(Collectors.toList());
			} catch (UsernameNotFoundException e) {
				return Collections.emptyList();
			}
		}
	}
}
