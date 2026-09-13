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

package org.springframework.security.docs.servlet.authentication.sendingtokentouser;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.mail.MailSender;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.authentication.ott.RedirectOneTimeTokenGenerationSuccessHandler;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;

// tag::snippet[]
@Component // <1>
public class MagicLinkOneTimeTokenGenerationSuccessHandler implements OneTimeTokenGenerationSuccessHandler {

	private final MailSender mailSender;

	private final OneTimeTokenGenerationSuccessHandler redirectHandler = new RedirectOneTimeTokenGenerationSuccessHandler("/ott/sent");

	public MagicLinkOneTimeTokenGenerationSuccessHandler(MailSender mailSender) {
		this.mailSender = mailSender;
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken oneTimeToken) throws IOException, ServletException {
		UriComponentsBuilder builder = UriComponentsBuilder.fromUriString(UrlUtils.buildFullRequestUrl(request))
				.replacePath(request.getContextPath())
				.replaceQuery(null)
				.fragment(null)
				.path("/login/ott")
				.queryParam("token", oneTimeToken.getTokenValue()); // <2>
		String magicLink = builder.toUriString();
		String email = getUserEmail(oneTimeToken.getUsername()); // <3>
		SimpleMailMessage message = new SimpleMailMessage();
		message.setTo(email);
		message.setSubject("Your Spring Security One Time Token");
		message.setText("Use the following link to sign in into the application: " + magicLink);
		this.mailSender.send(message); // <4>
		this.redirectHandler.handle(request, response, oneTimeToken); // <5>
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