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
package org.springframework.security.oauth2.client.authentication.ui;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import java.util.List;

/**
 * @author Joe Grandja
 */
public class DefaultOAuth2LoginPageGeneratingFilter extends AbstractLoginPageGeneratingFilter {
	private final ClientRegistrationRepository clientRegistrationRepository;

	public DefaultOAuth2LoginPageGeneratingFilter(ClientRegistrationRepository clientRegistrationRepository) {
		super();
		Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
		this.clientRegistrationRepository = clientRegistrationRepository;
	}

	@Override
	public String generateLoginPageHtml(HttpServletRequest request, boolean loginError, boolean logoutSuccess) {
		StringBuilder sb = new StringBuilder();

		sb.append("<html><head><title>OAuth2 Client Login Page</title></head><body>\n");

		if (loginError) {
			sb.append("<p style=\"color:red;\">Your login attempt was not successful, try again.<br/><br/>Reason: ");
			sb.append(this.resolveErrorMessage(request));
			sb.append("</p>\n");
		}

		if (logoutSuccess) {
			sb.append("<p style=\"color:green;\">You have been logged out.</p>\n");
		}

		sb.append("<h3>Login with Client:</h3>");
		sb.append("<div>");
		sb.append("<ul>\n");
		sb.append(this.generateClientsListHtml());
		sb.append("</ul>");
		sb.append("</div>");

		sb.append("</body></html>");

		return sb.toString();
	}

	private String generateClientsListHtml() {
		StringBuilder sb = new StringBuilder();
		List<ClientRegistration> clientRegistrations = this.clientRegistrationRepository.getRegistrations();

		for (ClientRegistration clientRegistration : clientRegistrations) {
			sb.append("<li>\n");
			sb.append("<a href=\"");
			sb.append(this.getAuthenticationUrl() + "/" + clientRegistration.getClientAlias());
			sb.append("\">\n");
			sb.append("<span>").append(clientRegistration.getClientName()).append("</span>\n");
			sb.append("</a>\n");
			sb.append("</li>\n");
		}
		if (clientRegistrations.isEmpty()) {
			sb.append("<li style=\"color:red;\">No available clients configured</li>\n");
		}

		return sb.toString();
	}
}