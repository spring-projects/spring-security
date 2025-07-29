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

package org.springframework.security.config.http;

import java.util.List;

import org.springframework.beans.factory.BeanCreationException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.annotation.SecurityAnnotationScanner;
import org.springframework.security.web.access.channel.ChannelDecisionManagerImpl;

/**
 * Used as a factory bean to create config attribute values for the
 * <tt>requires-channel</tt> attribute.
 *
 * @author Luke Taylor
 * @since 3.0
 * @deprecated In modern Spring Security APIs, each API manages its own configuration
 * context. As such there is no direct replacement for this interface. In the case of
 * method security, please see {@link SecurityAnnotationScanner} and
 * {@link AuthorizationManager}. In the case of channel security, please see
 * {@code HttpsRedirectFilter}. In the case of web security, please see
 * {@link AuthorizationManager}.
 */
@Deprecated
public final class ChannelAttributeFactory {

	private static final String OPT_REQUIRES_HTTP = "http";

	private static final String OPT_REQUIRES_HTTPS = "https";

	private static final String OPT_ANY_CHANNEL = "any";

	private ChannelAttributeFactory() {
	}

	public static List<ConfigAttribute> createChannelAttributes(String requiredChannel) {
		String channelConfigAttribute = switch (requiredChannel) {
			case OPT_REQUIRES_HTTPS -> "REQUIRES_SECURE_CHANNEL";
			case OPT_REQUIRES_HTTP -> "REQUIRES_INSECURE_CHANNEL";
			case OPT_ANY_CHANNEL -> ChannelDecisionManagerImpl.ANY_CHANNEL;
			default -> throw new BeanCreationException("Unknown channel attribute " + requiredChannel);
		};
		return SecurityConfig.createList(channelConfigAttribute);
	}

}
