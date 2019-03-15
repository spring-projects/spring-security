/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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
package org.springframework.security.cas;

/**
 * Sets the appropriate parameters for CAS's implementation of SAML (which is not
 * guaranteed to be actually SAML compliant).
 *
 * @author Scott Battaglia
 * @since 3.0
 */
public final class SamlServiceProperties extends ServiceProperties {

	public static final String DEFAULT_SAML_ARTIFACT_PARAMETER = "SAMLart";

	public static final String DEFAULT_SAML_SERVICE_PARAMETER = "TARGET";

	public SamlServiceProperties() {
		super.setArtifactParameter(DEFAULT_SAML_ARTIFACT_PARAMETER);
		super.setServiceParameter(DEFAULT_SAML_SERVICE_PARAMETER);
	}
}
