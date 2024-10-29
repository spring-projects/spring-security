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

import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.util.Arrays;
import java.util.Collections;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.DefaultCsrfToken;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.ImmutableCredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.TestCredentialRecord;
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.RequestBuilder;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.util.HtmlUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

@ExtendWith(MockitoExtension.class)
class DefaultWebAuthnRegistrationPageGeneratingFilterTests {

	@Mock
	private PublicKeyCredentialUserEntityRepository userEntities;

	@Mock
	private UserCredentialRepository userCredentials;

	@Test
	void constructorWhenNullUserEntities() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new DefaultWebAuthnRegistrationPageGeneratingFilter(null, this.userCredentials))
			.withMessage("userEntities cannot be null");
	}

	@Test
	void constructorWhenNullUserCredentials() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new DefaultWebAuthnRegistrationPageGeneratingFilter(this.userEntities, null))
			.withMessage("userCredentials cannot be null");
	}

	@Test
	void doFilterWhenNotMatchThenNoInteractions() throws Exception {
		MockMvc mockMvc = mockMvc();
		mockMvc.perform(get("/not-match"));

		verifyNoInteractions(this.userEntities, this.userCredentials);
	}

	@Test
	void doFilterThenCsrfDataAttrsPresent() throws Exception {
		PublicKeyCredentialUserEntity userEntity = ImmutablePublicKeyCredentialUserEntity.builder()
			.name("user")
			.id(Bytes.random())
			.displayName("User")
			.build();
		given(this.userEntities.findByUsername(any())).willReturn(userEntity);
		given(this.userCredentials.findByUserId(userEntity.getId()))
			.willReturn(Arrays.asList(TestCredentialRecord.userCredential().build()));
		String body = bodyAsString(matchingRequest());
		assertThat(body).contains("setupRegistration({\"X-CSRF-TOKEN\" : \"CSRF_TOKEN\"}");
		assertThat(body.replaceAll("\\s", "")).contains("""
				<form class="delete-form no-margin" method="post" action="/webauthn/register/NauGCN7bZ5jEBwThcde51g">
					<input type="hidden" name="method" value="delete">
					<input type="hidden" name="_csrf" value="CSRF_TOKEN">
					<button class="primary small" type="submit">Delete</button>
				</form>""".replaceAll("\\s", ""));
	}

	@Test
	void doFilterWhenNullPublicKeyCredentialUserEntityThenNoResults() throws Exception {
		String body = bodyAsString(matchingRequest());
		assertThat(body).contains("No Passkeys");
		verifyNoInteractions(this.userCredentials);
	}

	@Test
	void doFilterWhenNoCredentialsThenNoResults() throws Exception {
		PublicKeyCredentialUserEntity userEntity = ImmutablePublicKeyCredentialUserEntity.builder()
			.name("user")
			.id(Bytes.random())
			.displayName("User")
			.build();
		given(this.userEntities.findByUsername(any())).willReturn(userEntity);
		given(this.userCredentials.findByUserId(userEntity.getId())).willReturn(Collections.emptyList());
		String body = bodyAsString(matchingRequest());
		assertThat(body).contains("No Passkeys");
		verify(this.userCredentials).findByUserId(any());
	}

	@Test
	void doFilterWhenResultsThenDisplayed() throws Exception {
		PublicKeyCredentialUserEntity userEntity = ImmutablePublicKeyCredentialUserEntity.builder()
			.name("user")
			.id(Bytes.random())
			.displayName("User")
			.build();

		ImmutableCredentialRecord credential = TestCredentialRecord.userCredential()
			.created(LocalDateTime.of(2024, 9, 17, 10, 10, 42, 999_999_999).toInstant(ZoneOffset.UTC))
			.lastUsed(LocalDateTime.of(2024, 9, 18, 11, 11, 42, 999_999_999).toInstant(ZoneOffset.UTC))
			.build();
		given(this.userEntities.findByUsername(any())).willReturn(userEntity);
		given(this.userCredentials.findByUserId(userEntity.getId())).willReturn(Arrays.asList(credential));
		String body = bodyAsString(matchingRequest());
		assertThat(body).isEqualTo(
				"""
						<html>
							<head>
								<meta charset="utf-8">
								<meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
								<meta name="description" content="">
								<meta name="author" content="">
								<title>WebAuthn Registration</title>
								<link href="/default-ui.css" rel="stylesheet" />
								<script type="text/javascript" src="/login/webauthn.js"></script>
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
									document.addEventListener("DOMContentLoaded",() => setupRegistration({"X-CSRF-TOKEN" : "CSRF_TOKEN"}, "", ui));
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
											<tr class="v-middle">
												<td>label</td>
												<td>2024-09-17T10:10:42Z</td>
												<td>2024-09-18T11:11:42Z</td>
												<td class="center">0</td>
												<td>
													<form class="delete-form no-margin" method="post" action="/webauthn/register/NauGCN7bZ5jEBwThcde51g">
														<input type="hidden" name="method" value="delete">
														<input type="hidden" name="_csrf" value="CSRF_TOKEN">
														<button class="primary small" type="submit">Delete</button>
													</form>
												</td>
											</tr>
										</tbody>
									</table>
								</div>
							</body>
						</html>
						""");
	}

	@Test
	void doFilterWhenResultsContainEntitiesThenEncoded() throws Exception {
		String label = "<script>alert('Hello');</script>";
		String htmlEncodedLabel = HtmlUtils.htmlEscape(label);
		assertThat(label).isNotEqualTo(htmlEncodedLabel);
		PublicKeyCredentialUserEntity userEntity = ImmutablePublicKeyCredentialUserEntity.builder()
			.name("user")
			.id(Bytes.random())
			.displayName("User")
			.build();
		ImmutableCredentialRecord credential = TestCredentialRecord.userCredential().label(label).build();
		given(this.userEntities.findByUsername(any())).willReturn(userEntity);
		given(this.userCredentials.findByUserId(userEntity.getId())).willReturn(Arrays.asList(credential));
		String body = bodyAsString(matchingRequest());
		assertThat(body).doesNotContain(credential.getLabel());
		assertThat(body).contains(htmlEncodedLabel);
	}

	@Test
	void doFilterWhenContextEmptyThenUrlsEmptyPrefix() throws Exception {
		PublicKeyCredentialUserEntity userEntity = ImmutablePublicKeyCredentialUserEntity.builder()
			.name("user")
			.id(Bytes.random())
			.displayName("User")
			.build();
		ImmutableCredentialRecord credential = TestCredentialRecord.userCredential().build();
		given(this.userEntities.findByUsername(any())).willReturn(userEntity);
		given(this.userCredentials.findByUserId(userEntity.getId())).willReturn(Arrays.asList(credential));
		String body = bodyAsString(matchingRequest());
		assertThat(body).contains("<script type=\"text/javascript\" src=\"/login/webauthn.js\"></script>");
		assertThat(body).contains(
				"document.addEventListener(\"DOMContentLoaded\",() => setupRegistration({\"X-CSRF-TOKEN\" : \"CSRF_TOKEN\"}, \"\",");
	}

	@Test
	void doFilterWhenContextNotEmptyThenUrlsPrefixed() throws Exception {
		PublicKeyCredentialUserEntity userEntity = ImmutablePublicKeyCredentialUserEntity.builder()
			.name("user")
			.id(Bytes.random())
			.displayName("User")
			.build();
		ImmutableCredentialRecord credential = TestCredentialRecord.userCredential().build();
		given(this.userEntities.findByUsername(any())).willReturn(userEntity);
		given(this.userCredentials.findByUserId(userEntity.getId())).willReturn(Arrays.asList(credential));
		String body = bodyAsString(matchingRequest("/foo"));
		assertThat(body).contains("<script type=\"text/javascript\" src=\"/foo/login/webauthn.js\"></script>");
		assertThat(body).contains("setupRegistration({\"X-CSRF-TOKEN\" : \"CSRF_TOKEN\"}, \"/foo\",");
	}

	private String bodyAsString(RequestBuilder request) throws Exception {
		MockMvc mockMvc = mockMvc();
		MvcResult result = mockMvc.perform(request).andReturn();
		MockHttpServletResponse response = result.getResponse();
		assertThat(response.getStatus()).isEqualTo(HttpStatus.OK.value());
		assertThat(response.getContentType()).isEqualTo(MediaType.TEXT_HTML_VALUE);
		return response.getContentAsString();
	}

	private MockHttpServletRequestBuilder matchingRequest() {
		return matchingRequest("");
	}

	private MockHttpServletRequestBuilder matchingRequest(String contextPath) {
		DefaultCsrfToken token = new DefaultCsrfToken("X-CSRF-TOKEN", "_csrf", "CSRF_TOKEN");
		return get(contextPath + "/webauthn/register").contextPath(contextPath)
			.requestAttr(CsrfToken.class.getName(), token);
	}

	private MockMvc mockMvc() {
		return MockMvcBuilders.standaloneSetup(new Object())
			.addFilter(new DefaultWebAuthnRegistrationPageGeneratingFilter(this.userEntities, this.userCredentials))
			.build();
	}

}
