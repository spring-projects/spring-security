/*
 * Copyright 2002-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.data.repository.query;

import org.springframework.data.repository.query.spi.EvaluationContextExtension;
import org.springframework.data.repository.query.spi.EvaluationContextExtensionSupport;
import org.springframework.data.repository.query.spi.Function;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;

import java.util.Map;

/**
 * <p>
 * By defining this object as a Bean, Spring Security is exposed as SpEL expressions for
 * creating Spring Data queries.
 * </p>
 *
 * <p>
 * With Java based configuration, we can define the bean using the following:
 * </p>
 *
 * <p>
 * For example, if you return a UserDetails that extends the following User object:
 * </p>
 *
 * <pre>
 * @Entity
 * public class User {
 *     @GeneratedValue(strategy = GenerationType.AUTO)
 *     @Id
 *     private Long id;
 * 
 *     ...
 * </pre>
 *
 * <p>
 * And you have a Message object that looks like the following:
 * </p>
 *
 * <pre>
 * @Entity
 * public class Message {
 *     @Id
 *     @GeneratedValue(strategy = GenerationType.AUTO)
 *     private Long id;
 * 
 *     @OneToOne
 *     private User to;
 * 
 *     ...
 * </pre>
 *
 * You can use the following {@code Query} annotation to search for only messages that are
 * to the current user:
 *
 * <pre>
 * &#064;Repository
 * public interface SecurityMessageRepository extends MessageRepository {
 * 
 * 	&#064;Query(&quot;select m from Message m where m.to.id = ?#{ principal?.id }&quot;)
 * 	List&lt;Message&gt; findAll();
 * }
 * </pre>
 *
 * This works because the principal in this instance is a User which has an id field on
 * it.
 *
 * @since 4.0
 * @author Rob Winch
 */
public class SecurityEvaluationContextExtension extends EvaluationContextExtensionSupport {
	private Authentication authentication;

	/**
	 * Creates a new instance that uses the current {@link Authentication} found on the
	 * {@link org.springframework.security.core.context.SecurityContextHolder}.
	 */
	public SecurityEvaluationContextExtension() {
	}

	/**
	 * Creates a new instance that always uses the same {@link Authentication} object.
	 *
	 * @param authentication the {@link Authentication} to use
	 */
	public SecurityEvaluationContextExtension(Authentication authentication) {
		this.authentication = authentication;
	}

	public String getExtensionId() {
		return "security";
	}

	@Override
	public Object getRootObject() {
		Authentication authentication = getAuthentication();
		return new SecurityExpressionRoot(authentication) {
		};
	}

	private Authentication getAuthentication() {
		if (authentication != null) {
			return authentication;
		}

		SecurityContext context = SecurityContextHolder.getContext();
		return context.getAuthentication();
	}
}