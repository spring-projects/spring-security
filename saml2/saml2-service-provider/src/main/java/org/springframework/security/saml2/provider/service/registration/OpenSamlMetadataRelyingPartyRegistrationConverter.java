/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.saml2.provider.service.registration;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collection;

class OpenSamlMetadataRelyingPartyRegistrationConverter {

	private final OpenSamlMetadataAssertingPartyDetailsConverter converter = new OpenSamlMetadataAssertingPartyDetailsConverter();

	Collection<RelyingPartyRegistration.Builder> convert(InputStream source) {
		Collection<RelyingPartyRegistration.Builder> builders = new ArrayList<>();
		for (RelyingPartyRegistration.AssertingPartyDetails.Builder builder : this.converter.convert(source)) {
			builders.add(new RelyingPartyRegistration.Builder(builder));
		}
		return builders;
	}

}
