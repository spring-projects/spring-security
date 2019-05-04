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

package org.springframework.security.webauthn.options;

import com.webauthn4j.data.PublicKeyCredentialDescriptor;
import com.webauthn4j.data.PublicKeyCredentialType;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.client.AuthenticationExtensionClientInput;
import com.webauthn4j.data.extension.client.AuthenticationExtensionsClientInputs;
import org.junit.Test;

import java.util.Collections;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

public class AssertionOptionsTest {

	@Test
	public void equals_hashCode_test() {
		String rpId = "rpId";
		Challenge challenge = new DefaultChallenge();
		Long authenticationTimeout = 1000L;
		List<PublicKeyCredentialDescriptor> credentialIds = Collections.singletonList(new PublicKeyCredentialDescriptor(PublicKeyCredentialType.PUBLIC_KEY, new byte[32], null));
		AuthenticationExtensionsClientInputs<AuthenticationExtensionClientInput> authenticationExtensionsClientInputs = new AuthenticationExtensionsClientInputs<>();

		AssertionOptions instanceA =
				new AssertionOptions(challenge, authenticationTimeout, rpId, credentialIds, authenticationExtensionsClientInputs);
		AssertionOptions instanceB =
				new AssertionOptions(challenge, authenticationTimeout, rpId, credentialIds, authenticationExtensionsClientInputs);

		assertThat(instanceA).isEqualTo(instanceB);
		assertThat(instanceA).hasSameHashCodeAs(instanceB);
	}

}
