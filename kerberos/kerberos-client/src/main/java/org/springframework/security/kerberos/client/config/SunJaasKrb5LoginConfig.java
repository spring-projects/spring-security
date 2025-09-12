/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.kerberos.client.config;

import java.util.HashMap;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;

/**
 * Implementation of {@link Configuration} which uses Sun's JAAS Krb5LoginModule.
 *
 * @author Nelson Rodrigues
 * @author Janne Valkealahti
 *
 */
public class SunJaasKrb5LoginConfig extends Configuration implements InitializingBean {

	private static final Log LOG = LogFactory.getLog(SunJaasKrb5LoginConfig.class);

	private String servicePrincipal;

	private Resource keyTabLocation;

	private Boolean useTicketCache = false;

	private Boolean isInitiator = false;

	private Boolean debug = false;

	private String keyTabLocationAsString;

	public void setServicePrincipal(String servicePrincipal) {
		this.servicePrincipal = servicePrincipal;
	}

	public void setKeyTabLocation(Resource keyTabLocation) {
		this.keyTabLocation = keyTabLocation;
	}

	public void setUseTicketCache(Boolean useTicketCache) {
		this.useTicketCache = useTicketCache;
	}

	public void setIsInitiator(Boolean isInitiator) {
		this.isInitiator = isInitiator;
	}

	public void setDebug(Boolean debug) {
		this.debug = debug;
	}

	@Override
	public void afterPropertiesSet() throws Exception {
		Assert.hasText(this.servicePrincipal, "servicePrincipal must be specified");

		if (this.keyTabLocation != null && this.keyTabLocation instanceof ClassPathResource) {
			LOG.warn(
					"Your keytab is in the classpath. This file needs special protection and shouldn't be in the classpath. JAAS may also not be able to load this file from classpath.");
		}

		if (!this.useTicketCache) {
			Assert.notNull(this.keyTabLocation, "keyTabLocation must be specified when useTicketCache is false");
		}

		if (this.keyTabLocation != null) {
			this.keyTabLocationAsString = this.keyTabLocation.getURL().toExternalForm();
			if (this.keyTabLocationAsString.startsWith("file:")) {
				this.keyTabLocationAsString = this.keyTabLocationAsString.substring(5);
			}
		}
	}

	@Override
	public AppConfigurationEntry[] getAppConfigurationEntry(String name) {
		HashMap<String, String> options = new HashMap<>();

		options.put("principal", this.servicePrincipal);

		if (this.keyTabLocation != null) {
			options.put("useKeyTab", "true");
			options.put("keyTab", this.keyTabLocationAsString);
			options.put("storeKey", "true");
		}

		options.put("doNotPrompt", "true");

		if (this.useTicketCache) {
			options.put("useTicketCache", "true");
			options.put("renewTGT", "true");
		}

		options.put("isInitiator", this.isInitiator.toString());
		options.put("debug", this.debug.toString());

		return new AppConfigurationEntry[] { new AppConfigurationEntry("com.sun.security.auth.module.Krb5LoginModule",
				AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, options), };
	}

}
