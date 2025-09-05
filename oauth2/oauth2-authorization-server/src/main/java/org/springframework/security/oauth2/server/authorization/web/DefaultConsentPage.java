/*
 * Copyright 2020-2023 the original author or authors.
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
package org.springframework.security.oauth2.server.authorization.web;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;

/**
 * For internal use only.
 *
 * @author Joe Grandja
 */
final class DefaultConsentPage {

	private static final MediaType TEXT_HTML_UTF8 = new MediaType("text", "html", StandardCharsets.UTF_8);

	private DefaultConsentPage() {
	}

	static void displayConsent(HttpServletRequest request, HttpServletResponse response, String clientId,
			Authentication principal, Set<String> requestedScopes, Set<String> authorizedScopes, String state,
			Map<String, String> additionalParameters) throws IOException {

		String consentPage = generateConsentPage(request, clientId, principal, requestedScopes, authorizedScopes, state,
				additionalParameters);
		response.setContentType(TEXT_HTML_UTF8.toString());
		response.setContentLength(consentPage.getBytes(StandardCharsets.UTF_8).length);
		response.getWriter().write(consentPage);
	}

	private static String generateConsentPage(HttpServletRequest request, String clientId, Authentication principal,
			Set<String> requestedScopes, Set<String> authorizedScopes, String state,
			Map<String, String> additionalParameters) {
		Set<String> scopesToAuthorize = new HashSet<>();
		Set<String> scopesPreviouslyAuthorized = new HashSet<>();
		for (String scope : requestedScopes) {
			if (authorizedScopes.contains(scope)) {
				scopesPreviouslyAuthorized.add(scope);
			}
			else if (!scope.equals(OidcScopes.OPENID)) {
				// openid scope does not require consent
				scopesToAuthorize.add(scope);
			}
		}

		// https://datatracker.ietf.org/doc/html/rfc8628#section-3.3.1
		// The server SHOULD display
		// the "user_code" to the user and ask them to verify that it matches
		// the "user_code" being displayed on the device to confirm they are
		// authorizing the correct device.
		String userCode = additionalParameters.get(OAuth2ParameterNames.USER_CODE);

		// @formatter:off
		StringBuilder builder = new StringBuilder();
		builder.append("<!DOCTYPE html>");
		builder.append("<html lang=\"en\">");
		builder.append("<head>");
		builder.append("    <meta charset=\"utf-8\">");
		builder.append("    <meta name=\"viewport\" content=\"width=device-width, initial-scale=1, shrink-to-fit=no\">");
		builder.append("    <link rel=\"stylesheet\" href=\"https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/css/bootstrap.min.css\" integrity=\"sha384-JcKb8q3iqJ61gNV9KGb8thSsNjpSL0n8PARn9HuZOnIxN0hoP+VmmDGMN5t9UJ0Z\" crossorigin=\"anonymous\">");
		builder.append("    <title>Consent required</title>");
		builder.append("	<script>");
		builder.append("		function cancelConsent() {");
		builder.append("			document.consent_form.reset();");
		builder.append("			document.consent_form.submit();");
		builder.append("		}");
		builder.append("	</script>");
		builder.append("</head>");
		builder.append("<body>");
		builder.append("<div class=\"container\">");
		builder.append("    <div class=\"py-5\">");
		builder.append("        <h1 class=\"text-center\">Consent required</h1>");
		builder.append("    </div>");
		builder.append("    <div class=\"row\">");
		builder.append("        <div class=\"col text-center\">");
		builder.append("            <p><span class=\"font-weight-bold text-primary\">" + clientId + "</span> wants to access your account <span class=\"font-weight-bold\">" + principal.getName() + "</span></p>");
		builder.append("        </div>");
		builder.append("    </div>");
		if (userCode != null) {
			builder.append("    <div class=\"row\">");
			builder.append("        <div class=\"col text-center\">");
			builder.append("            <p class=\"alert alert-warning\">You have provided the code <span class=\"font-weight-bold\">" + userCode + "</span>. Verify that this code matches what is shown on your device.</p>");
			builder.append("        </div>");
			builder.append("    </div>");
		}
		builder.append("    <div class=\"row pb-3\">");
		builder.append("        <div class=\"col text-center\">");
		builder.append("            <p>The following permissions are requested by the above app.<br/>Please review these and consent if you approve.</p>");
		builder.append("        </div>");
		builder.append("    </div>");
		builder.append("    <div class=\"row\">");
		builder.append("        <div class=\"col text-center\">");
		builder.append("            <form name=\"consent_form\" method=\"post\" action=\"" + request.getRequestURI() + "\">");
		builder.append("                <input type=\"hidden\" name=\"client_id\" value=\"" + clientId + "\">");
		builder.append("                <input type=\"hidden\" name=\"state\" value=\"" + state + "\">");
		if (userCode != null) {
			builder.append("                <input type=\"hidden\" name=\"user_code\" value=\"" + userCode + "\">");
		}

		for (String scope : scopesToAuthorize) {
			builder.append("                <div class=\"form-group form-check py-1\">");
			builder.append("                    <input class=\"form-check-input\" type=\"checkbox\" name=\"scope\" value=\"" + scope + "\" id=\"" + scope + "\">");
			builder.append("                    <label class=\"form-check-label\" for=\"" + scope + "\">" + scope + "</label>");
			builder.append("                </div>");
		}

		if (!scopesPreviouslyAuthorized.isEmpty()) {
			builder.append("                <p>You have already granted the following permissions to the above app:</p>");
			for (String scope : scopesPreviouslyAuthorized) {
				builder.append("                <div class=\"form-group form-check py-1\">");
				builder.append("                    <input class=\"form-check-input\" type=\"checkbox\" name=\"scope\" id=\"" + scope + "\" checked disabled>");
				builder.append("                    <label class=\"form-check-label\" for=\"" + scope + "\">" + scope + "</label>");
				builder.append("                </div>");
			}
		}

		builder.append("                <div class=\"form-group pt-3\">");
		builder.append("                    <button class=\"btn btn-primary btn-lg\" type=\"submit\" id=\"submit-consent\">Submit Consent</button>");
		builder.append("                </div>");
		builder.append("                <div class=\"form-group\">");
		builder.append("                    <button class=\"btn btn-link regular\" type=\"button\" onclick=\"cancelConsent();\" id=\"cancel-consent\">Cancel</button>");
		builder.append("                </div>");
		builder.append("            </form>");
		builder.append("        </div>");
		builder.append("    </div>");
		builder.append("    <div class=\"row pt-4\">");
		builder.append("        <div class=\"col text-center\">");
		builder.append("            <p><small>Your consent to provide access is required.<br/>If you do not approve, click Cancel, in which case no information will be shared with the app.</small></p>");
		builder.append("        </div>");
		builder.append("    </div>");
		builder.append("</div>");
		builder.append("</body>");
		builder.append("</html>");
		// @formatter:on

		return builder.toString();
	}

}
