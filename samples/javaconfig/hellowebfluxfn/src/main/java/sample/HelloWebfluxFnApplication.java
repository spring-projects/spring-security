/*
 * Copyright 2002-2017 the original author or authors.
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

package sample;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.ReactiveAdapterRegistry;
import org.springframework.http.server.reactive.HttpHandler;
import org.springframework.http.server.reactive.ReactorHttpHandlerAdapter;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryAuthenticationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.config.web.server.AuthorizeExchangeBuilder;
import org.springframework.security.config.web.server.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.reactive.result.method.annotation.AuthenticationPrincipalArgumentResolver;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.security.web.server.context.WebSessionSecurityContextRepository;
import org.springframework.web.reactive.DispatcherHandler;
import org.springframework.web.reactive.config.EnableWebFlux;
import org.springframework.web.reactive.config.WebFluxConfigurer;
import org.springframework.web.reactive.function.server.HandlerStrategies;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.reactive.result.method.annotation.ArgumentResolverConfigurer;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;
import reactor.ipc.netty.NettyContext;
import reactor.ipc.netty.http.server.HttpServer;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.config.web.server.HttpSecurity.http;
import static org.springframework.web.reactive.function.server.RequestPredicates.GET;
import static org.springframework.web.reactive.function.server.RequestPredicates.accept;
import static org.springframework.web.reactive.function.server.RequestPredicates.contentType;
import static org.springframework.web.reactive.function.server.RouterFunctions.route;

/**
 * @author Rob Winch
 * @since 5.0
 */
@Configuration
@EnableWebFlux
@ComponentScan
public class HelloWebfluxFnApplication {
	@Value("${server.port:8080}")
	private int port = 8080;

	public static void main(String[] args) throws Exception {
		try(AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(HelloWebfluxFnApplication.class)) {
			context.getBean(NettyContext.class).onClose().block();
		}
	}

	@Bean
	public NettyContext nettyContext(UserController userController, WebFilter springSecurityFilterChain) {
		RouterFunction<ServerResponse> route = route(
				GET("/principal"), userController::principal).andRoute(
				GET("/users"), userController::users).andRoute(
				GET("/admin"), userController::admin);

		HandlerStrategies handlerStrategies = HandlerStrategies.builder()
			.webFilter(springSecurityFilterChain).build();

		HttpHandler handler = RouterFunctions.toHttpHandler(route, handlerStrategies);
		ReactorHttpHandlerAdapter adapter = new ReactorHttpHandlerAdapter(handler);
		HttpServer httpServer = HttpServer.create("localhost", port);
		return httpServer.newHandler(adapter).block();
	}

	@Bean
	WebFilter springSecurityFilterChain(ReactiveAuthenticationManager manager) throws Exception {
		HttpSecurity http = http();
		http.securityContextRepository(new WebSessionSecurityContextRepository());
		http.authenticationManager(manager);
		http.httpBasic();

		AuthorizeExchangeBuilder authorize = http.authorizeExchange();
		authorize.antMatchers("/admin/**").hasRole("ADMIN");
		authorize.antMatchers("/users/{user}/**").access(this::currentUserMatchesPath);
		authorize.anyExchange().authenticated();
		return http.build();
	}

	private Mono<AuthorizationDecision> currentUserMatchesPath(Mono<Authentication> authentication, AuthorizationContext context) {
		return authentication
			.map( a -> context.getVariables().get("user").equals(a.getName()))
			.map( granted -> new AuthorizationDecision(granted));
	}

	@Bean
	public ReactiveAuthenticationManager authenticationManager(UserRepositoryUserDetailsRepository udr) {
		return new UserDetailsRepositoryAuthenticationManager(udr);
	}
}
