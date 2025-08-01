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

package org.springframework.security.oauth2.client.annotation;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

import org.springframework.core.annotation.AliasFor;

/**
 * This annotation can be added to the method of an interface based HTTP client created
 * using {@link org.springframework.web.service.invoker.HttpServiceProxyFactory} to
 * automatically associate an OAuth token with the request.
 *
 * @author Rob Winch
 * @since 7.0
 * @see org.springframework.security.oauth2.client.web.client.ClientRegistrationIdProcessor
 */
@Target({ ElementType.METHOD, ElementType.ANNOTATION_TYPE })
@Retention(RetentionPolicy.RUNTIME)
@Documented
public @interface ClientRegistrationId {

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
