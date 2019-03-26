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
/**
 * Password encoding implementations. Apart from the "null" implementations, they are all based on
 * password hashing using digest functions. See the
 * <a href="https://docs.spring.io/spring-security/site/docs/3.0.x/reference/core-services.html#core-services-password-encoding">
 * reference manual</a> for more information.
 * <p>
 * Third part implementations such as those provided by <a href="http://www.jasypt.org/springsecurity.html">Jasypt</a>
 * can also be used.
 */
package org.springframework.security.authentication.encoding;

