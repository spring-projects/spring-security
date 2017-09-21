/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.config.oauth2.client;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.support.PropertiesLoaderUtils;

import java.io.IOException;
import java.util.Map;

/**
 * A resource loader for OAuth 2.0 client template(s) properties.
 *
 * @author Joe Grandja
 * @since 5.0.0
 */
public final class OAuth2ClientTemplatePropertiesLoader {

	public static final String CLIENT_TEMPLATES_PROPERTY_PREFIX = "spring.security.oauth2.client.templates";

	private static final String CLIENT_TEMPLATES_RESOURCE_LOCATION = "spring-security-oauth2-client-templates.properties";

	private OAuth2ClientTemplatePropertiesLoader() {
	}

	public static Map<String, Object> loadClientTemplates() {
		try {
			return (Map) PropertiesLoaderUtils.loadProperties(
				new ClassPathResource(CLIENT_TEMPLATES_RESOURCE_LOCATION, OAuth2ClientTemplatePropertiesLoader.class));
		} catch (IOException ioe) {
			throw new RuntimeException("Failed to load OAuth 2.0 client templates resource: "
					+ CLIENT_TEMPLATES_RESOURCE_LOCATION, ioe);
		}
	}
}
