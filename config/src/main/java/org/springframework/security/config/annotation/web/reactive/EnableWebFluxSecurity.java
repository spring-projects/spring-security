/*
 * Copyright 2002-2017 the original author or authors.
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

package org.springframework.security.config.annotation.web.reactive;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.web.server.ServerHttpSecurity;

import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Add this annotation to a {@code Configuration} class to have Spring Security WebFlux
 * support added. User's can then create one or more {@link ServerHttpSecurity}
 * {@code Bean} instances.
 *
 * A minimal configuration can be found below:
 *
 * <pre class="code">
 * &#064;EnableWebFluxSecurity
 * public class MyMinimalSecurityConfiguration {
 *
 *     &#064;Bean
 *     public MapReactiveUserDetailsService userDetailsService() {
 *          UserDetails user = User.withDefaultPasswordEncoder()
 *               .username("user")
 *               .password("password")
 *               .roles("USER")
 *               .build();
 *          return new MapReactiveUserDetailsService(user);
 *     }
 * }
 *
 * Below is the same as our minimal configuration, but explicitly declaring the
 * {@code ServerHttpSecurity}.
 *
 * <pre class="code">
 * &#064;EnableWebFluxSecurity
 * public class MyExplicitSecurityConfiguration {
 *     // @formatter:off
 *     &#064;Bean
 *     public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http) {
 *          http
 *               .authorizeExchange()
 *                    .anyExchange().authenticated()
 *                         .and()
 *                    .httpBasic().and()
 *                    .formLogin();
 *          return http.build();
 *     }
 *     // @formatter:on
 *
 *     // @formatter:off
 *     &#064;Bean
 *     public MapReactiveUserDetailsService userDetailsService() {
 *          UserDetails user = User.withDefaultPasswordEncoder()
 *               .username("user")
 *               .password("password")
 *               .roles("USER")
 *               .build();
 *          return new MapReactiveUserDetailsService(user);
 *     }
 *     // @formatter:on
 * }
 *
 * @author Rob Winch
 * @since 5.0
 */
@Retention(RetentionPolicy.RUNTIME)
@Target(ElementType.TYPE)
@Documented
@Import({ServerHttpSecurityConfiguration.class, WebFluxSecurityConfiguration.class,
		ReactiveOAuth2ClientImportSelector.class})
@Configuration
public @interface EnableWebFluxSecurity {
}
