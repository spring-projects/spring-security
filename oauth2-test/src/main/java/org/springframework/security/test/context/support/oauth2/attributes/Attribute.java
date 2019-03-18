/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.springframework.security.test.context.support.oauth2.attributes;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * <p>
 * Annotation to create an entry in a {@link java.util.Map Map&lt;String, Object&gt;} such as
 * {@link org.springframework.security.oauth2.jwt.Jwt JWT} headers or claims.
 * </p>
 * <p>
 * {@link #parser()} can be referenced either by fully qualified name or simple name.
 * </p>
 * <p>
 * See {@link Parser} and its already provided implementations: {@link AttributeParsersHelper#DEFAULT_PARSERS}
 * </p>
 * Sample usage:<br>
 *
 * <pre>
 * &#64;WithMockJwt(
 *   claims = {
 *     &#64;Attribute(name = JwtClaimNames.AUD, value = "first audience", parser = "StringListStringParser"),
 *     &#64;Attribute(name = JwtClaimNames.AUD, value = "second audience", parser = "StringListStringParser"),
 *     &#64;Attribute(name = JwtClaimNames.ISS, value = "https://test-issuer.org", parser = "UrlStringParser"),
 *     &#64;Attribute(name = "machin", value = "chose"),
 *     &#64;Attribute(name = "truc", value = "bidule", parser = "your.fancy.ParserImpl")})
 * </pre>
 *
 * This will create
 * <ul>
 * <li>an {@code audience} claim with a value being a {@code List<String>} with two entries</li>
 * <li>an {@code issuer} claim with a value being a {@code java.net.URL} instance</li>
 * <li>a {@code machin} claim with {@code chose} String as value (default parser is
 * {@link org.springframework.security.test.context.support.oauth2.attributes.NoOpStringParser NoOpStringParser})</li>
 * <li>a {@code truc} claim whith an instance of what {@code your.fancy.ParserImpl} is designed to build from
 * {@code bidule} string as value</li>
 * </ul>
 *
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 *
 */
@Target({ ElementType.METHOD, ElementType.TYPE })
@Retention(RetentionPolicy.RUNTIME)
public @interface Attribute {

	/**
	 * @return the key in the {@link java.util.Map Map&lt;String, Object&gt;}
	 */
	String name();

	/**
	 * @return a value to be transformed using "parser" before being put as value in {@link java.util.Map Map&lt;String,
	 * Object&gt;}
	 */
	String value();

	/**
	 * @return a {@link org.springframework.security.test.context.support.oauth2.attributes.Parser Parser}
	 * implementation class name
	 */
	String parser() default "NoOpStringParser";

}
