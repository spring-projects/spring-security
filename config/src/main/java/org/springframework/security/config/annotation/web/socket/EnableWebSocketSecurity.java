/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.annotation.web.socket;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.context.annotation.Import;

/**
 * Allows configuring WebSocket Authorization.
 *
 * <p>
 * For example:
 * </p>
 *
 * <pre>
 * &#064;Configuration
 * &#064;EnableWebSocketSecurity
 * public class WebSocketSecurityConfig {
 *
 * 	&#064;Bean
 * 	AuthorizationManager&lt;Message&lt;?&gt;&gt; authorizationManager(MessageMatcherDelegatingAuthorizationManager.Builder messages) {
 * 		messages.simpDestMatchers(&quot;/user/queue/errors&quot;).permitAll()
 * 				.simpDestMatchers(&quot;/admin/**&quot;).hasRole(&quot;ADMIN&quot;)
 * 				.anyMessage().authenticated();
 *		return messages.build();
 * 	}
 * }
 * </pre>
 *
 * @author Josh Cummings
 * @since 5.8
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
@Import(WebSocketMessageBrokerSecurityConfiguration.class)
public @interface EnableWebSocketSecurity {

}
