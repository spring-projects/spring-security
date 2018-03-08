/*
 * Copyright 2002-2018 the original author or authors.
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
package org.springframework.security.oauth2.client.annotation;

import org.springframework.core.annotation.AliasFor;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.web.method.annotation.OAuth2ClientArgumentResolver;
import org.springframework.security.oauth2.core.OAuth2AccessToken;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * This annotation may be used to resolve a method parameter into an argument value
 * for the following types: {@link ClientRegistration}, {@link OAuth2AuthorizedClient}
 * and {@link OAuth2AccessToken}.
 *
 * <p>
 * For example:
 * <pre>
 * &#64;Controller
 * public class MyController {
 *     &#64;GetMapping("/client-registration")
 *     public String clientRegistration(@OAuth2Client("login-client") ClientRegistration clientRegistration) {
 *         // do something with clientRegistration
 *     }
 *
 *     &#64;GetMapping("/authorized-client")
 *     public String authorizedClient(@OAuth2Client("login-client") OAuth2AuthorizedClient authorizedClient) {
 *         // do something with authorizedClient
 *     }
 *
 *     &#64;GetMapping("/access-token")
 *     public String accessToken(@OAuth2Client("login-client") OAuth2AccessToken accessToken) {
 *         // do something with accessToken
 *     }
 * }
 * </pre>
 *
 * @author Joe Grandja
 * @since 5.1
 * @see OAuth2ClientArgumentResolver
 */
@Target({ ElementType.PARAMETER, ElementType.ANNOTATION_TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface OAuth2Client {

	/**
	 * Sets the client registration identifier.
	 *
	 * @return the client registration identifier
	 */
	@AliasFor("value")
	String registrationId() default "";

	/**
	 * The default attribute for this annotation.
	 * This is an alias for {@link #registrationId()}.
	 * For example, {@code @OAuth2Client("login-client")} is equivalent to
	 * {@code @OAuth2Client(registrationId="login-client")}.
	 *
	 * @return the client registration identifier
	 */
	@AliasFor("registrationId")
	String value() default "";

}
