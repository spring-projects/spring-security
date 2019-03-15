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

package sample;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.*;
import org.springframework.http.server.reactive.HttpHandler;
import org.springframework.http.server.reactive.ReactorHttpHandlerAdapter;
import org.springframework.web.reactive.config.EnableWebFlux;
import org.springframework.web.reactive.function.server.HandlerStrategies;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.server.WebFilter;
import reactor.ipc.netty.NettyContext;
import reactor.ipc.netty.http.server.HttpServer;

import static org.springframework.web.reactive.function.server.RequestPredicates.GET;
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

	@Profile("default")
	@Bean
	public NettyContext nettyContext(HttpHandler handler) {
		ReactorHttpHandlerAdapter adapter = new ReactorHttpHandlerAdapter(handler);
		HttpServer httpServer = HttpServer.create("localhost", this.port);
		return httpServer.newHandler(adapter).block();
	}

	@Bean
	public RouterFunction<ServerResponse> routes(HelloUserController userController) {
		return route(
			GET("/"), userController::hello);
	}

	@Bean
	public HttpHandler httpHandler(RouterFunction<ServerResponse> routes, WebFilter springSecurityFilterChain) {
		HandlerStrategies handlerStrategies = HandlerStrategies.builder()
			.webFilter(springSecurityFilterChain)
			.build();

		return RouterFunctions.toHttpHandler(routes, handlerStrategies);
	}

}
