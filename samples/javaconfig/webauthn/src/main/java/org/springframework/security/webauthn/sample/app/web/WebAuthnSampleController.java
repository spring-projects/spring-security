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

package org.springframework.security.webauthn.sample.app.web;

import com.webauthn4j.util.Base64UrlUtil;
import com.webauthn4j.util.UUIDUtil;
import com.webauthn4j.util.exception.WebAuthnException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.MultiFactorAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.webauthn.WebAuthnDataConverter;
import org.springframework.security.webauthn.WebAuthnOptionWebHelper;
import org.springframework.security.webauthn.WebAuthnRegistrationRequest;
import org.springframework.security.webauthn.WebAuthnRegistrationRequestValidator;
import org.springframework.security.webauthn.authenticator.WebAuthnAuthenticator;
import org.springframework.security.webauthn.authenticator.WebAuthnAuthenticatorImpl;
import org.springframework.security.webauthn.authenticator.WebAuthnAuthenticatorTransport;
import org.springframework.security.webauthn.exception.WebAuthnAuthenticationException;
import org.springframework.security.webauthn.userdetails.InMemoryWebAuthnAndPasswordUserDetailsManager;
import org.springframework.security.webauthn.userdetails.WebAuthnAndPasswordUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.Base64Utils;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.HttpServletRequest;
import javax.validation.Valid;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Login controller
 */
@SuppressWarnings("SameReturnValue")
@Controller
public class WebAuthnSampleController {

	private final Log logger = LogFactory.getLog(getClass());

	private static final String REDIRECT_LOGIN = "redirect:/login";
	private static final String REDIRECT_SIGNUP = "redirect:/signup";

	private static final String VIEW_SIGNUP_SIGNUP = "signup/signup";
	private static final String VIEW_LOGIN_LOGIN = "login/login";
	private static final String VIEW_LOGIN_AUTHENTICATOR_LOGIN = "login/authenticator-login";

	private static final String VIEW_DASHBOARD_DASHBOARD = "dashboard/dashboard";

	@Autowired
	private InMemoryWebAuthnAndPasswordUserDetailsManager webAuthnUserDetailsService;

	@Autowired
	private WebAuthnRegistrationRequestValidator registrationRequestValidator;

	@Autowired
	private WebAuthnOptionWebHelper webAuthnOptionWebHelper;

	@Autowired
	private WebAuthnDataConverter webAuthnDataConverter;

	@Autowired
	private PasswordEncoder passwordEncoder;

	@ModelAttribute
	public void addAttributes(Model model, HttpServletRequest request) {
		model.addAttribute("webAuthnChallenge", webAuthnOptionWebHelper.getChallenge(request));
		model.addAttribute("webAuthnCredentialIds", webAuthnOptionWebHelper.getCredentialIds());
	}

	@RequestMapping(value = "/")
	public String index(Model model) {
		return REDIRECT_SIGNUP;
	}

	@RequestMapping(value = "/dashboard")
	public String dashboard(Model model) {
		return VIEW_DASHBOARD_DASHBOARD;
	}

	@RequestMapping(value = "/signup", method = RequestMethod.GET)
	public String template(Model model) {
		UserCreateForm userCreateForm = new UserCreateForm();
		UUID userHandle = UUID.randomUUID();
		String userHandleStr = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(UUIDUtil.convertUUIDToBytes(userHandle));
		userCreateForm.setUserHandle(userHandleStr);
		model.addAttribute("userForm", userCreateForm);
		return VIEW_SIGNUP_SIGNUP;
	}

	@RequestMapping(value = "/signup", method = RequestMethod.POST)
	public String create(HttpServletRequest request, @Valid @ModelAttribute("userForm") UserCreateForm userCreateForm, BindingResult result, Model model) {

		if (result.hasErrors()) {
			return VIEW_SIGNUP_SIGNUP;
		}

		WebAuthnRegistrationRequest webAuthnRegistrationRequest = new WebAuthnRegistrationRequest(
				request,
				userCreateForm.getAuthenticator().getClientDataJSON(),
				userCreateForm.getAuthenticator().getAttestationObject(),
				userCreateForm.getAuthenticator().getTransports(),
				userCreateForm.getAuthenticator().getClientExtensions()
		);
		try {
			registrationRequestValidator.validate(webAuthnRegistrationRequest);
		}
		catch (WebAuthnException | WebAuthnAuthenticationException e){
			logger.debug("WebAuthn registration request validation failed.", e);
			return VIEW_SIGNUP_SIGNUP;
		}

		AuthenticatorCreateForm sourceAuthenticator = userCreateForm.getAuthenticator();

		byte[] attestationObject = Base64UrlUtil.decode(sourceAuthenticator.getAttestationObject());
		byte[] authenticatorData = webAuthnDataConverter.extractAuthenticatorData(attestationObject);
		byte[] attestedCredentialData = webAuthnDataConverter.extractAttestedCredentialData(authenticatorData);
		byte[] credentialId = webAuthnDataConverter.extractCredentialId(attestedCredentialData);
		long signCount = webAuthnDataConverter.extractSignCount(authenticatorData);
		Set<WebAuthnAuthenticatorTransport> transports;
		if (sourceAuthenticator.getTransports() == null) {
			transports = null;
		}
		else {
			transports = sourceAuthenticator.getTransports().stream()
					.map(WebAuthnAuthenticatorTransport::create)
					.collect(Collectors.toSet());
		}

		List<WebAuthnAuthenticator> authenticators = new ArrayList<>();
		WebAuthnAuthenticator authenticator = new WebAuthnAuthenticatorImpl(
				credentialId,
				null,
				attestationObject,
				signCount,
				transports,
				sourceAuthenticator.getClientExtensions());

		authenticators.add(authenticator);

		byte[] userHandle = Base64Utils.decodeFromUrlSafeString(userCreateForm.getUserHandle());
		String username = userCreateForm.getUsername();
		String password = passwordEncoder.encode(userCreateForm.getPassword());
		List<GrantedAuthority> authorities = Collections.emptyList();
		boolean singleFactorAuthenticationAllowed = userCreateForm.isSingleFactorAuthenticationAllowed();
		WebAuthnAndPasswordUser user = new WebAuthnAndPasswordUser(userHandle, username, password, authenticators, singleFactorAuthenticationAllowed, authorities);


		try {
			webAuthnUserDetailsService.createUser(user);
		} catch (IllegalArgumentException ex) {
			return VIEW_SIGNUP_SIGNUP;
		}

		return REDIRECT_LOGIN;
	}

	@RequestMapping(value = "/login", method = RequestMethod.GET)
	public String login() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		if (authentication instanceof MultiFactorAuthenticationToken) {
			return VIEW_LOGIN_AUTHENTICATOR_LOGIN;
		} else {
			return VIEW_LOGIN_LOGIN;
		}
	}

}
