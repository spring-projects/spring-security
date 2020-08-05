/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.oauth2.client.annotation;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.web.method.annotation.OAuth2AuthorizedClientArgumentResolver;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * This annotation may be used to resolve a method parameter to an argument value of type
 * {@link OAuth2AuthorizedClient}.
 *
 * <p>
 * For example: <pre>
 * &#64;Controller
 * public class MyController {
 *     &#64;GetMapping("/authorized-client")
 *     public String authorizedClient(@RegisteredOAuth2AuthorizedClient("login-client") OAuth2AuthorizedClient authorizedClient) {
 *         // do something with authorizedClient
 *     }
 * }
 * </pre>
 *
 * @author Joe Grandja
 * @since 5.1
 * @see OAuth2AuthorizedClientArgumentResolver
 */
@Target({ ElementType.PARAMETER, ElementType.ANNOTATION_TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface RegisteredOAuth2AuthorizedClient {

	/**
	 * Sets the client registration identifier.
	 * @return the client registration identifier
	 */
	@AliasFor("value")
	String registrationId() default "";

	/**
	 * The default attribute for this annotation. This is an alias for
	 * {@link #registrationId()}. For example,
	 * {@code @RegisteredOAuth2AuthorizedClient("login-client")} is equivalent to
	 * {@code @RegisteredOAuth2AuthorizedClient(registrationId="login-client")}.
	 * @return the client registration identifier
	 */
	@AliasFor("registrationId")
	String value() default "";

}
