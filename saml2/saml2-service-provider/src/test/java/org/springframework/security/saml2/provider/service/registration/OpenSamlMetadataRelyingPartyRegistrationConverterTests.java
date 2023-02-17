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

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.core.io.ClassPathResource;

import static org.assertj.core.api.Assertions.assertThat;

public class OpenSamlMetadataRelyingPartyRegistrationConverterTests {

	private OpenSamlMetadataRelyingPartyRegistrationConverter converter = new OpenSamlMetadataRelyingPartyRegistrationConverter();

	private String metadata;

	@BeforeEach
	public void setup() throws Exception {
		ClassPathResource resource = new ClassPathResource("test-metadata.xml");
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream()))) {
			this.metadata = reader.lines().collect(Collectors.joining());
		}
	}

	// gh-12667
	@Test
	public void convertWhenDefaultsThenAssertingPartyInstanceOfOpenSaml() throws Exception {
		try (InputStream source = new ByteArrayInputStream(this.metadata.getBytes(StandardCharsets.UTF_8))) {
			this.converter.convert(source)
					.forEach((registration) -> assertThat(registration.build().getAssertingPartyDetails())
							.isInstanceOf(OpenSamlAssertingPartyDetails.class));
		}
	}

}
