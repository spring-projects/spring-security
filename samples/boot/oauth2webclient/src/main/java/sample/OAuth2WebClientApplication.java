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

package sample;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.security.oauth2.client.reactive.ReactiveOAuth2ClientAutoConfiguration;

/**
 * @author Joe Grandja
 */
// FIXME: Work around https://github.com/spring-projects/spring-boot/issues/14463
@SpringBootApplication(exclude = ReactiveOAuth2ClientAutoConfiguration.class)
public class OAuth2WebClientApplication {

	public static void main(String[] args) {
		SpringApplication.run(OAuth2WebClientApplication.class, args);
	}
}
