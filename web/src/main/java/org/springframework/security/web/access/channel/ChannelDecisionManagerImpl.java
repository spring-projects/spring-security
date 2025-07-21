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

package org.springframework.security.web.access.channel;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import jakarta.servlet.ServletException;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * Implementation of {@link ChannelDecisionManager}.
 * <p>
 * Iterates through each configured {@link ChannelProcessor}. If a
 * <code>ChannelProcessor</code> has any issue with the security of the request, it should
 * cause a redirect, exception or whatever other action is appropriate for the
 * <code>ChannelProcessor</code> implementation.
 * <p>
 * Once any response is committed (ie a redirect is written to the response object), the
 * <code>ChannelDecisionManagerImpl</code> will not iterate through any further
 * <code>ChannelProcessor</code>s.
 * <p>
 * The attribute "ANY_CHANNEL" if applied to a particular URL, the iteration through the
 * channel processors will be skipped (see SEC-494, SEC-335).
 *
 * @author Ben Alex
 * @deprecated no replacement is planned, though consider using a custom
 * {@link RequestMatcher} for any sophisticated decision-making
 */
@Deprecated
public class ChannelDecisionManagerImpl implements ChannelDecisionManager, InitializingBean {

	public static final String ANY_CHANNEL = "ANY_CHANNEL";

	private List<ChannelProcessor> channelProcessors;

	@Override
	public void afterPropertiesSet() {
		Assert.notEmpty(this.channelProcessors, "A list of ChannelProcessors is required");
	}

	@Override
	public void decide(FilterInvocation invocation, Collection<ConfigAttribute> config)
			throws IOException, ServletException {
		for (ConfigAttribute attribute : config) {
			if (ANY_CHANNEL.equals(attribute.getAttribute())) {
				return;
			}
		}
		for (ChannelProcessor processor : this.channelProcessors) {
			processor.decide(invocation, config);
			if (invocation.getResponse().isCommitted()) {
				break;
			}
		}
	}

	protected List<ChannelProcessor> getChannelProcessors() {
		return this.channelProcessors;
	}

	@SuppressWarnings("cast")
	public void setChannelProcessors(List<?> channelProcessors) {
		Assert.notEmpty(channelProcessors, "A list of ChannelProcessors is required");
		this.channelProcessors = new ArrayList<>(channelProcessors.size());
		for (Object currentObject : channelProcessors) {
			Assert.isInstanceOf(ChannelProcessor.class, currentObject, () -> "ChannelProcessor "
					+ currentObject.getClass().getName() + " must implement ChannelProcessor");
			this.channelProcessors.add((ChannelProcessor) currentObject);
		}
	}

	@Override
	public boolean supports(ConfigAttribute attribute) {
		if (ANY_CHANNEL.equals(attribute.getAttribute())) {
			return true;
		}
		for (ChannelProcessor processor : this.channelProcessors) {
			if (processor.supports(attribute)) {
				return true;
			}
		}
		return false;
	}

}
