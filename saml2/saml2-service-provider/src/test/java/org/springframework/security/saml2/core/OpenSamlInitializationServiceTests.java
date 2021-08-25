/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.saml2.core;

import org.junit.jupiter.api.Test;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;

import org.springframework.security.saml2.Saml2Exception;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * Tests for {@link OpenSamlInitializationService}
 *
 * @author Josh Cummings
 */
public class OpenSamlInitializationServiceTests {

	@Test
	public void initializeWhenInvokedMultipleTimesThenInitializesOnce() {
		OpenSamlInitializationService.initialize();
		XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
		assertThat(registry.getParserPool()).isNotNull();
		assertThatExceptionOfType(Saml2Exception.class)
				.isThrownBy(() -> OpenSamlInitializationService.requireInitialize((r) -> {
				})).withMessageContaining("OpenSAML was already initialized previously");
	}

}
