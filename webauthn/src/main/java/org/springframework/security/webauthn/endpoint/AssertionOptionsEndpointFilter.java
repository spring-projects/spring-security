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

package org.springframework.security.webauthn.endpoint;

import com.webauthn4j.converter.util.JsonConverter;
import com.webauthn4j.util.Base64UrlUtil;
import org.springframework.security.webauthn.options.AssertionOptions;
import org.springframework.security.webauthn.options.OptionsProvider;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import java.io.Serializable;
import java.util.List;
import java.util.stream.Collectors;

/**
 * A filter for providing WebAuthn option parameters to clients.
 * Clients can retrieve {@link AssertionOptions}.
 *
 * @author Yoshikazu Nojima
 */
public class AssertionOptionsEndpointFilter extends OptionsEndpointFilterBase {

	// ~ Static fields/initializers
	// =====================================================================================

	/**
	 * Default name of path suffix which will validate this filter.
	 */
	public static final String FILTER_URL = "/webauthn/assertion/options";


	//~ Instance fields
	// ================================================================================================

	protected OptionsProvider optionsProvider;


	// ~ Constructors
	// ===================================================================================================

	public AssertionOptionsEndpointFilter(OptionsProvider optionsProvider, JsonConverter jsonConverter) {
		super(jsonConverter);
		this.optionsProvider = optionsProvider;
		this.filterProcessesUrl = FILTER_URL;
		checkConfig();
	}


	// ~ Methods
	// ========================================================================================================

	@Override
	public void checkConfig() {
		Assert.notNull(optionsProvider, "optionsProvider must not be null");
		super.checkConfig();
	}

	@Override
	protected Serializable processRequest(HttpServletRequest request) {
		String loginUsername = getLoginUsername();
		AssertionOptions assertionOptions = optionsProvider.getAssertionOptions(request, loginUsername, null);
		List<WebAuthnPublicKeyCredentialDescriptor> credentials = assertionOptions.getAllowCredentials() == null ? null :
				assertionOptions.getAllowCredentials().stream()
						.map(credential -> new WebAuthnPublicKeyCredentialDescriptor(credential.getType(), Base64UrlUtil.encodeToString(credential.getId()), credential.getTransports()))
						.collect(Collectors.toList());

		return new AssertionOptionsResponse(
				assertionOptions.getChallenge(),
				assertionOptions.getTimeout(),
				assertionOptions.getRpId(),
				credentials,
				assertionOptions.getExtensions()
		);
	}
}
