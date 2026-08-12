/*
 * Copyright 2004-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *	  https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.docs.reactive.authentication.customizegeneratetokenrequest;

import java.time.Duration;
import org.springframework.context.annotation.Bean;
import org.springframework.security.web.server.authentication.ott.DefaultServerGenerateOneTimeTokenRequestResolver;
import org.springframework.security.web.server.authentication.ott.ServerGenerateOneTimeTokenRequestResolver;

public class SecurityConfig {

	// tag::config[]
	@Bean
  ServerGenerateOneTimeTokenRequestResolver generateOneTimeTokenRequestResolver() {
		DefaultServerGenerateOneTimeTokenRequestResolver resolver = new DefaultServerGenerateOneTimeTokenRequestResolver();
		resolver.setExpiresIn(Duration.ofMinutes(10));
		return resolver;
	}
	// end::config[]

}