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

package org.springframework.security.messaging.context;

import java.util.Stack;

import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.MessageHandler;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.support.ExecutorChannelInterceptor;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;

/**
 * An {@link ExecutorChannelInterceptor} that takes an {@link Authentication} from the
 * current {@link SecurityContext} (if any) in the
 * {@link #preSend(Message, MessageChannel)} callback and stores it into an
 * {@link #authenticationHeaderName} message header. Then sets the context from this
 * header in the {@link #beforeHandle(Message, MessageChannel, MessageHandler)} and
 * {@link #postReceive(Message, MessageChannel)} both of which typically happen on a
 * different thread.
 * <p>
 * Note: cannot be used in combination with a {@link SecurityContextChannelInterceptor} on
 * the same channel since both these interceptors modify a security context on a handling
 * and receiving operations.
 *
 * @author Artem Bilan
 * @since 6.2
 * @see SecurityContextChannelInterceptor
 */
public final class SecurityContextPropagationChannelInterceptor implements ExecutorChannelInterceptor {

	private static final ThreadLocal<Stack<SecurityContext>> originalContext = new ThreadLocal<>();

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();

	private SecurityContext empty = this.securityContextHolderStrategy.createEmptyContext();

	private final String authenticationHeaderName;

	private Authentication anonymous = new AnonymousAuthenticationToken("key", "anonymous",
			AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

	/**
	 * Create a new instance using the header of the name
	 * {@link SimpMessageHeaderAccessor#USER_HEADER}.
	 */
	public SecurityContextPropagationChannelInterceptor() {
		this(SimpMessageHeaderAccessor.USER_HEADER);
	}

	/**
	 * Create a new instance that uses the specified header to populate the
	 * {@link Authentication}.
	 * @param authenticationHeaderName the header name to populate the
	 * {@link Authentication}. Cannot be null.
	 */
	public SecurityContextPropagationChannelInterceptor(String authenticationHeaderName) {
		Assert.notNull(authenticationHeaderName, "authenticationHeaderName cannot be null");
		this.authenticationHeaderName = authenticationHeaderName;
	}

	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy strategy) {
		this.securityContextHolderStrategy = strategy;
		this.empty = this.securityContextHolderStrategy.createEmptyContext();
	}

	/**
	 * Configure an Authentication used for anonymous authentication. Default is: <pre>
	 * new AnonymousAuthenticationToken(&quot;key&quot;, &quot;anonymous&quot;,
	 * 		AuthorityUtils.createAuthorityList(&quot;ROLE_ANONYMOUS&quot;));
	 * </pre>
	 * @param authentication the Authentication used for anonymous authentication. Cannot
	 * be null.
	 */
	public void setAnonymousAuthentication(Authentication authentication) {
		Assert.notNull(authentication, "authentication cannot be null");
		this.anonymous = authentication;
	}

	@Override
	public Message<?> preSend(Message<?> message, MessageChannel channel) {
		Authentication authentication = this.securityContextHolderStrategy.getContext().getAuthentication();
		if (authentication == null) {
			authentication = this.anonymous;
		}
		return MessageBuilder.fromMessage(message).setHeader(this.authenticationHeaderName, authentication).build();
	}

	@Override
	public Message<?> beforeHandle(Message<?> message, MessageChannel channel, MessageHandler handler) {
		return postReceive(message, channel);
	}

	@Override
	public Message<?> postReceive(Message<?> message, MessageChannel channel) {
		setup(message);
		return message;
	}

	@Override
	public void afterMessageHandled(Message<?> message, MessageChannel channel, MessageHandler handler, Exception ex) {
		cleanup();
	}

	private void setup(Message<?> message) {
		Authentication authentication = message.getHeaders().get(this.authenticationHeaderName, Authentication.class);
		SecurityContext currentContext = this.securityContextHolderStrategy.getContext();
		Stack<SecurityContext> contextStack = originalContext.get();
		if (contextStack == null) {
			contextStack = new Stack<>();
			originalContext.set(contextStack);
		}
		contextStack.push(currentContext);
		SecurityContext context = this.securityContextHolderStrategy.createEmptyContext();
		context.setAuthentication(authentication);
		this.securityContextHolderStrategy.setContext(context);
	}

	private void cleanup() {
		Stack<SecurityContext> contextStack = originalContext.get();
		if (contextStack == null || contextStack.isEmpty()) {
			this.securityContextHolderStrategy.clearContext();
			originalContext.remove();
			return;
		}
		SecurityContext context = contextStack.pop();
		try {
			if (this.empty.equals(context)) {
				this.securityContextHolderStrategy.clearContext();
				originalContext.remove();
			}
			else {
				this.securityContextHolderStrategy.setContext(context);
			}
		}
		catch (Throwable ex) {
			this.securityContextHolderStrategy.clearContext();
		}
	}

}
