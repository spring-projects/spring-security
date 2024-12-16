/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.webauthn.registration;

import java.io.IOException;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A {@link jakarta.servlet.Filter} that renders a default WebAuthn registration page.
 *
 * @author Rob Winch
 * @author Daniel Garnier-Moiroux
 * @since 6.4
 */
public class DefaultWebAuthnRegistrationPageGeneratingFilter extends OncePerRequestFilter {

	private RequestMatcher matcher = AntPathRequestMatcher.antMatcher(HttpMethod.GET, "/webauthn/register");

	private final PublicKeyCredentialUserEntityRepository userEntities;

	private final UserCredentialRepository userCredentials;

	/**
	 * Creates a new instance.
	 * @param userEntities the {@link PublicKeyCredentialUserEntity}
	 * @param userCredentials
	 */
	public DefaultWebAuthnRegistrationPageGeneratingFilter(PublicKeyCredentialUserEntityRepository userEntities,
			UserCredentialRepository userCredentials) {
		Assert.notNull(userEntities, "userEntities cannot be null");
		Assert.notNull(userCredentials, "userCredentials cannot be null");
		this.userEntities = userEntities;
		this.userCredentials = userCredentials;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (!this.matcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		CsrfToken csrfToken = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
		response.setContentType(MediaType.TEXT_HTML_VALUE);
		response.setStatus(HttpServletResponse.SC_OK);
		String processedTemplate = HtmlTemplates.fromTemplate(HTML_TEMPLATE)
			.withValue("contextPath", request.getContextPath())
			.withRawHtml("csrfHeaders", renderCsrfHeader(csrfToken))
			.withRawHtml("passkeys", passkeyRows(request.getRemoteUser(), request.getContextPath(), csrfToken))
			.render();

		response.getWriter().write(processedTemplate);
	}

	private String passkeyRows(String username, String contextPath, CsrfToken csrfToken) {
		PublicKeyCredentialUserEntity userEntity = this.userEntities.findByUsername(username);
		List<CredentialRecord> credentials = (userEntity != null)
				? this.userCredentials.findByUserId(userEntity.getId()) : Collections.emptyList();
		if (credentials.isEmpty()) {
			return """
										<tr><td colspan="5">No Passkeys</td></tr>
					""";
		}
		return credentials.stream()
			.map((credentialRecord) -> renderPasskeyRow(credentialRecord, contextPath, csrfToken))
			.collect(Collectors.joining("\n"));
	}

	private String renderPasskeyRow(CredentialRecord credential, String contextPath, CsrfToken csrfToken) {
		return HtmlTemplates.fromTemplate(PASSKEY_ROW_TEMPLATE)
			.withValue("label", credential.getLabel())
			.withValue("created", formatInstant(credential.getCreated()))
			.withValue("lastUsed", formatInstant(credential.getLastUsed()))
			.withValue("signatureCount", credential.getSignatureCount())
			.withValue("credentialId", credential.getCredentialId().toBase64UrlString())
			.withValue("csrfParameterName", csrfToken.getParameterName())
			.withValue("csrfToken", csrfToken.getToken())
			.withValue("contextPath", contextPath)
			.render();
	}

	private static String formatInstant(Instant created) {
		return ZonedDateTime.ofInstant(created, ZoneId.of("UTC"))
			.truncatedTo(ChronoUnit.SECONDS)
			.format(DateTimeFormatter.ISO_INSTANT);
	}

	private String renderCsrfHeader(CsrfToken csrfToken) {
		return HtmlTemplates.fromTemplate(CSRF_HEADERS)
			.withValue("headerName", csrfToken.getHeaderName())
			.withValue("headerValue", csrfToken.getToken())
			.render();
	}

	private static final String HTML_TEMPLATE = """
			<html>
				<head>
					<meta charset="utf-8">
					<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
					<meta name="description" content="">
					<meta name="author" content="">
					<title>WebAuthn Registration</title>
					<link href="{{contextPath}}/default-ui.css" rel="stylesheet" />
					<script type="text/javascript" src="{{contextPath}}/login/webauthn.js"></script>
					<script type="text/javascript">
					<!--
						const ui = {
							getRegisterButton: function() {
								return document.getElementById('register')
							},
							getSuccess: function() {
								return document.getElementById('success')
							},
							getError: function() {
								return document.getElementById('error')
							},
							getLabelInput: function() {
								return document.getElementById('label')
							},
							getDeleteForms: function() {
								return Array.from(document.getElementsByClassName("delete-form"))
							},
						}
						document.addEventListener("DOMContentLoaded",() => setupRegistration({{csrfHeaders}}, "{{contextPath}}", ui));
					//-->
					</script>
				</head>
				<body>
					<div class="content">
						<h2 class="center">WebAuthn Registration</h2>
						<form class="default-form" method="post" action="#" onclick="return false">
							<div id="success" class="alert alert-success" role="alert">Success!</div>
							<div id="error" class="alert alert-danger" role="alert"></div>
							<p>
								<label for="label" class="screenreader">Passkey Label</label>
								<input type="text" id="label" name="label" placeholder="Passkey Label" required autofocus>
							</p>
							<button id="register" class="primary" type="submit">Register</button>
						</form>
						<table class="table table-striped">
							<thead>
								<tr class="table-header">
									<th>Label</th>
									<th>Created</th>
									<th>Last Used</th>
									<th>Signature Count</th>
									<th>Delete</th>
								</tr>
							</thead>
							<tbody>
			{{passkeys}}
							</tbody>
						</table>
					</div>
				</body>
			</html>
			""";

	private static final String PASSKEY_ROW_TEMPLATE = """
								<tr class="v-middle">
									<td>{{label}}</td>
									<td>{{created}}</td>
									<td>{{lastUsed}}</td>
									<td class="center">{{signatureCount}}</td>
									<td>
										<form class="delete-form no-margin" method="post" action="{{contextPath}}/webauthn/register/{{credentialId}}">
											<input type="hidden" name="method" value="delete">
											<input type="hidden" name="{{csrfParameterName}}" value="{{csrfToken}}">
											<button class="primary small" type="submit">Delete</button>
										</form>
									</td>
								</tr>
			""";

	private static final String CSRF_HEADERS = """
			{"{{headerName}}" : "{{headerValue}}"}""";

}
