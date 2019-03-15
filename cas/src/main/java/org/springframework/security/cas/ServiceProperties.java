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

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

/**
 * Stores properties related to this CAS service.
 * <p>
 * Each web application capable of processing CAS tickets is known as a service. This
 * class stores the properties that are relevant to the local CAS service, being the
 * application that is being secured by Spring Security.
 *
 * @author Ben Alex
 */
public class ServiceProperties implements InitializingBean {

	public static final String DEFAULT_CAS_ARTIFACT_PARAMETER = "ticket";

	public static final String DEFAULT_CAS_SERVICE_PARAMETER = "service";

	// ~ Instance fields
	// ================================================================================================

	private String service;

	private boolean authenticateAllArtifacts;

	private boolean sendRenew = false;

	private String artifactParameter = DEFAULT_CAS_ARTIFACT_PARAMETER;

	private String serviceParameter = DEFAULT_CAS_SERVICE_PARAMETER;

	// ~ Methods
	// ========================================================================================================

	public void afterPropertiesSet() throws Exception {
		Assert.hasLength(this.service, "service cannot be empty.");
		Assert.hasLength(this.artifactParameter, "artifactParameter cannot be empty.");
		Assert.hasLength(this.serviceParameter, "serviceParameter cannot be empty.");
	}

	/**
	 * Represents the service the user is authenticating to.
	 * <p>
	 * This service is the callback URL belonging to the local Spring Security System for
	 * Spring secured application. For example,
	 *
	 * <pre>
	 * https://www.mycompany.com/application/login/cas
	 * </pre>
	 *
	 * @return the URL of the service the user is authenticating to
	 */
	public final String getService() {
		return this.service;
	}

	/**
	 * Indicates whether the <code>renew</code> parameter should be sent to the CAS login
	 * URL and CAS validation URL.
	 * <p>
	 * If <code>true</code>, it will force CAS to authenticate the user again (even if the
	 * user has previously authenticated). During ticket validation it will require the
	 * ticket was generated as a consequence of an explicit login. High security
	 * applications would probably set this to <code>true</code>. Defaults to
	 * <code>false</code>, providing automated single sign on.
	 *
	 * @return whether to send the <code>renew</code> parameter to CAS
	 */
	public final boolean isSendRenew() {
		return this.sendRenew;
	}

	public final void setSendRenew(final boolean sendRenew) {
		this.sendRenew = sendRenew;
	}

	public final void setService(final String service) {
		this.service = service;
	}

	public final String getArtifactParameter() {
		return this.artifactParameter;
	}

	/**
	 * Configures the Request Parameter to look for when attempting to see if a CAS ticket
	 * was sent from the server.
	 *
	 * @param artifactParameter the id to use. Default is "ticket".
	 */
	public final void setArtifactParameter(final String artifactParameter) {
		this.artifactParameter = artifactParameter;
	}

	/**
	 * Configures the Request parameter to look for when attempting to send a request to
	 * CAS.
	 *
	 * @return the service parameter to use. Default is "service".
	 */
	public final String getServiceParameter() {
		return this.serviceParameter;
	}

	public final void setServiceParameter(final String serviceParameter) {
		this.serviceParameter = serviceParameter;
	}

	public final boolean isAuthenticateAllArtifacts() {
		return this.authenticateAllArtifacts;
	}

	/**
	 * If true, then any non-null artifact (ticket) should be authenticated. Additionally,
	 * the service will be determined dynamically in order to ensure the service matches
	 * the expected value for this artifact.
	 *
	 * @param authenticateAllArtifacts
	 */
	public final void setAuthenticateAllArtifacts(
			final boolean authenticateAllArtifacts) {
		this.authenticateAllArtifacts = authenticateAllArtifacts;
	}
}
