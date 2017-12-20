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

import org.apache.catalina.Context;
import org.apache.catalina.startup.Tomcat;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.server.reactive.HttpHandler;
import org.springframework.http.server.reactive.ServletHttpHandlerAdapter;
import org.springframework.web.reactive.config.EnableWebFlux;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;

import javax.servlet.Servlet;

/**
 * @author Rob Winch
 * @since 5.0
 */
@Configuration
@EnableWebFlux
@ComponentScan
public class WebfluxFormApplication {
	@Value("${server.port:8080}")
	private int port = 8080;

	public static void main(String[] args) throws Exception {
		Object lock = new Object();
		try(AnnotationConfigApplicationContext context = new AnnotationConfigApplicationContext(
			WebfluxFormApplication.class)) {
			synchronized (lock) {
				lock.wait();
			}
		}
	}

	@Bean(destroyMethod = "stop", initMethod = "start")
	public Tomcat tomcat(ApplicationContext context) throws Exception {
		HttpHandler handler = WebHttpHandlerBuilder.applicationContext(context)
			.build();
		Servlet servlet = new ServletHttpHandlerAdapter(handler);
		Tomcat server = new Tomcat();
		server.setPort(this.port);
		server.getServer().setPort(this.port);
		Context rootContext = server.addContext("", System.getProperty("java.io.tmpdir"));
		Tomcat.addServlet(rootContext, "servlet", servlet);
		rootContext.addServletMapping("/", "servlet");
		return server;
	}
}
