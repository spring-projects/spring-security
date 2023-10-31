/*
 * Copyright 2002-2016 the original author or authors.
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
import org.springframework.security.web.access.channel.ChannelDecisionManagerImpl;

/**
 * Used as a factory bean to create config attribute values for the
 * <tt>requires-channel</tt> attribute.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public final class ChannelAttributeFactory {

	private static final String OPT_REQUIRES_HTTP = "http";

	private static final String OPT_REQUIRES_HTTPS = "https";

	private static final String OPT_ANY_CHANNEL = "any";

	private ChannelAttributeFactory() {
	}

	public static List<ConfigAttribute> createChannelAttributes(String requiredChannel) {
		String channelConfigAttribute;
		if (requiredChannel.equals(OPT_REQUIRES_HTTPS)) {
			channelConfigAttribute = "REQUIRES_SECURE_CHANNEL";
		}
		else if (requiredChannel.equals(OPT_REQUIRES_HTTP)) {
			channelConfigAttribute = "REQUIRES_INSECURE_CHANNEL";
		}
		else if (requiredChannel.equals(OPT_ANY_CHANNEL)) {
			channelConfigAttribute = ChannelDecisionManagerImpl.ANY_CHANNEL;
		}
		else {
			throw new BeanCreationException("Unknown channel attribute " + requiredChannel);
		}
		return SecurityConfig.createList(channelConfigAttribute);
	}

}
