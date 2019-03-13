/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.test.context.support.oauth2.properties;

/**
 * De-serializes an annotation String value into an Object of type T
 *
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 *
 * @param <T> what
 * {@link org.springframework.security.test.context.support.oauth2.properties.Property#value() @Property.value}
 * should be turned into
 *
 */
public interface PropertyParser<T> {

	/**
	 * @param value String to de-serialize
	 * @return an Object
	 */
	T parse(String value);

}
