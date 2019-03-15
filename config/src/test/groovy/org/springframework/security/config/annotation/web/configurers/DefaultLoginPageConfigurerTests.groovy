/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.config.annotation.web.configurers

import javax.servlet.http.HttpSession

import org.springframework.context.annotation.Configuration
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.config.annotation.AnyObjectPostProcessor
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.BaseWebConfig;
import org.springframework.security.config.annotation.web.configurers.DefaultLoginPageConfigurer;
import org.springframework.security.web.FilterChainProxy
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler
import org.springframework.security.web.authentication.ui.DefaultLoginPageGeneratingFilter

/**
 * Tests to verify that {@link DefaultLoginPageConfigurer} works
 *
 * @author Rob Winch
 *
 */
public class DefaultLoginPageConfigurerTests extends BaseSpringSpec {
	def "http/form-login default login generating page"() {
		setup:
			loadConfig(DefaultLoginPageConfig)
		when:
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			findFilter(DefaultLoginPageGeneratingFilter)
			response.getRedirectedUrl() == "http://localhost/login"
		when: "request the login page"
			super.setup()
			request.requestURI = "/login"
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.getContentAsString() == """<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">
    <title>Please sign in</title>
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M" crossorigin="anonymous">
    <link href="https://getbootstrap.com/docs/4.0/examples/signin/signin.css" rel="stylesheet" crossorigin="anonymous"/>
  </head>
  <body>
     <div class="container">
      <form class="form-signin" method="post" action="/login">
        <h2 class="form-signin-heading">Please sign in</h2>
        <p>
          <label for="username" class="sr-only">Username</label>
          <input type="text" id="username" name="username" class="form-control" placeholder="Username" required autofocus>
        </p>
        <p>
          <label for="password" class="sr-only">Password</label>
          <input type="password" id="password" name="password" class="form-control" placeholder="Password" required>
        </p>
<input name="${csrfToken.parameterName}" type="hidden" value="${csrfToken.token}" />
        <button class="btn btn-lg btn-primary btn-block" type="submit">Sign in</button>
      </form>
</div>
</body></html>"""
		when: "fail to log in"
			super.setup()
			request.servletPath = "/login"
			request.method = "POST"
			springSecurityFilterChain.doFilter(request,response,chain)
		then: "sent to login error page"
			response.getRedirectedUrl() == "/login?error"
		when: "request the error page"
			HttpSession session = request.session
			super.setup()
			request.session = session
			request.requestURI = "/login"
			request.queryString = "error"
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.getContentAsString() == """<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">
    <title>Please sign in</title>
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M" crossorigin="anonymous">
    <link href="https://getbootstrap.com/docs/4.0/examples/signin/signin.css" rel="stylesheet" crossorigin="anonymous"/>
  </head>
  <body>
     <div class="container">
      <form class="form-signin" method="post" action="/login">
        <h2 class="form-signin-heading">Please sign in</h2>
<div class="alert alert-danger" role="alert">Bad credentials</div>        <p>
          <label for="username" class="sr-only">Username</label>
          <input type="text" id="username" name="username" class="form-control" placeholder="Username" required autofocus>
        </p>
        <p>
          <label for="password" class="sr-only">Password</label>
          <input type="password" id="password" name="password" class="form-control" placeholder="Password" required>
        </p>
<input name="${csrfToken.parameterName}" type="hidden" value="${csrfToken.token}" />
        <button class="btn btn-lg btn-primary btn-block" type="submit">Sign in</button>
      </form>
</div>
</body></html>"""
		when: "login success"
			super.setup()
			request.servletPath = "/login"
			request.method = "POST"
			request.parameters.username = ["user"] as String[]
			request.parameters.password = ["password"] as String[]
			springSecurityFilterChain.doFilter(request,response,chain)
		then: "sent to default succes page"
			response.getRedirectedUrl() == "/"
	}

	def "logout success renders"() {
		setup:
			loadConfig(DefaultLoginPageConfig)
		when: "logout success"
			request.requestURI = "/login"
			request.queryString = "logout"
			request.method = "GET"
			springSecurityFilterChain.doFilter(request,response,chain)
		then: "sent to default success page"
			response.getContentAsString() == """<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">
    <title>Please sign in</title>
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M" crossorigin="anonymous">
    <link href="https://getbootstrap.com/docs/4.0/examples/signin/signin.css" rel="stylesheet" crossorigin="anonymous"/>
  </head>
  <body>
     <div class="container">
      <form class="form-signin" method="post" action="/login">
        <h2 class="form-signin-heading">Please sign in</h2>
<div class="alert alert-success" role="alert">You have been signed out</div>        <p>
          <label for="username" class="sr-only">Username</label>
          <input type="text" id="username" name="username" class="form-control" placeholder="Username" required autofocus>
        </p>
        <p>
          <label for="password" class="sr-only">Password</label>
          <input type="password" id="password" name="password" class="form-control" placeholder="Password" required>
        </p>
<input name="${csrfToken.parameterName}" type="hidden" value="${csrfToken.token}" />
        <button class="btn btn-lg btn-primary btn-block" type="submit">Sign in</button>
      </form>
</div>
</body></html>"""
	}

	@Configuration
	static class DefaultLoginPageConfig extends BaseWebConfig {
		@Override
		protected void configure(HttpSecurity http) {
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin()
		}
	}

	def "custom logout success handler prevents rendering"() {
		setup:
			loadConfig(DefaultLoginPageCustomLogoutSuccessHandlerConfig)
		when: "logout success"
			request.requestURI = "/login"
			request.queryString = "logout"
			request.method = "GET"
			springSecurityFilterChain.doFilter(request,response,chain)
		then: "default success page is NOT rendered (application is in charge of it)"
			response.getContentAsString() == ""
	}

	@Configuration
	static class DefaultLoginPageCustomLogoutSuccessHandlerConfig extends BaseWebConfig {
		@Override
		protected void configure(HttpSecurity http) {
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.logout()
					.logoutSuccessHandler(new SimpleUrlLogoutSuccessHandler())
					.and()
				.formLogin()
		}
	}

	def "custom logout success url prevents rendering"() {
		setup:
			loadConfig(DefaultLoginPageCustomLogoutConfig)
		when: "logout success"
			request.requestURI = "/login"
			request.queryString = "logout"
			request.method = "GET"
			springSecurityFilterChain.doFilter(request,response,chain)
		then: "default success page is NOT rendered (application is in charge of it)"
			response.getContentAsString() == ""
	}

	@Configuration
	static class DefaultLoginPageCustomLogoutConfig extends BaseWebConfig {
		@Override
		protected void configure(HttpSecurity http) {
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.logout()
					.logoutSuccessUrl("/login?logout")
					.and()
				.formLogin()
		}
	}

	def "http/form-login default login with remember me"() {
		setup:
			loadConfig(DefaultLoginPageWithRememberMeConfig)
		when: "request the login page"
			super.setup()
			request.requestURI = "/login"
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.getContentAsString() == """<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">
    <title>Please sign in</title>
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M" crossorigin="anonymous">
    <link href="https://getbootstrap.com/docs/4.0/examples/signin/signin.css" rel="stylesheet" crossorigin="anonymous"/>
  </head>
  <body>
     <div class="container">
      <form class="form-signin" method="post" action="/login">
        <h2 class="form-signin-heading">Please sign in</h2>
        <p>
          <label for="username" class="sr-only">Username</label>
          <input type="text" id="username" name="username" class="form-control" placeholder="Username" required autofocus>
        </p>
        <p>
          <label for="password" class="sr-only">Password</label>
          <input type="password" id="password" name="password" class="form-control" placeholder="Password" required>
        </p>
<p><input type='checkbox' name='remember-me'/> Remember me on this computer.</p>
<input name="${csrfToken.parameterName}" type="hidden" value="${csrfToken.token}" />
        <button class="btn btn-lg btn-primary btn-block" type="submit">Sign in</button>
      </form>
</div>
</body></html>"""
	}

	@Configuration
	static class DefaultLoginPageWithRememberMeConfig extends BaseWebConfig {
		@Override
		protected void configure(HttpSecurity http) {
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin()
					.and()
				.rememberMe()
		}
	}

	def "http/form-login default login with openid"() {
		setup:
			loadConfig(DefaultLoginPageWithOpenIDConfig)
		when: "request the login page"
			request.requestURI = "/login"
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.getContentAsString() == """<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">
    <title>Please sign in</title>
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M" crossorigin="anonymous">
    <link href="https://getbootstrap.com/docs/4.0/examples/signin/signin.css" rel="stylesheet" crossorigin="anonymous"/>
  </head>
  <body>
     <div class="container">
      <form name="oidf" class="form-signin" method="post" action="/login/openid">
        <h2 class="form-signin-heading">Login with OpenID Identity</h2>
        <p>
          <label for="username" class="sr-only">Identity</label>
          <input type="text" id="username" name="openid_identifier" class="form-control" placeholder="Username" required autofocus>
        </p>
<input name="${csrfToken.parameterName}" type="hidden" value="${csrfToken.token}" />
        <button class="btn btn-lg btn-primary btn-block" type="submit">Sign in</button>
      </form>
</div>
</body></html>"""
	}

	@Configuration
	static class DefaultLoginPageWithOpenIDConfig extends BaseWebConfig {
		@Override
		protected void configure(HttpSecurity http) {
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.openidLogin()
		}
	}

	def "http/form-login default login with openid, form login, and rememberme"() {
		setup:
			loadConfig(DefaultLoginPageWithFormLoginOpenIDRememberMeConfig)
		when: "request the login page"
			request.requestURI = "/login"
			springSecurityFilterChain.doFilter(request,response,chain)
		then:
			response.getContentAsString() == """<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
    <meta name="description" content="">
    <meta name="author" content="">
    <title>Please sign in</title>
    <link href="https://maxcdn.bootstrapcdn.com/bootstrap/4.0.0-beta/css/bootstrap.min.css" rel="stylesheet" integrity="sha384-/Y6pD6FV/Vv2HJnA6t+vslU6fwYXjCFtcEpHbNJ0lyAFsXTsjBbfaDjzALeQsN6M" crossorigin="anonymous">
    <link href="https://getbootstrap.com/docs/4.0/examples/signin/signin.css" rel="stylesheet" crossorigin="anonymous"/>
  </head>
  <body>
     <div class="container">
      <form class="form-signin" method="post" action="/login">
        <h2 class="form-signin-heading">Please sign in</h2>
        <p>
          <label for="username" class="sr-only">Username</label>
          <input type="text" id="username" name="username" class="form-control" placeholder="Username" required autofocus>
        </p>
        <p>
          <label for="password" class="sr-only">Password</label>
          <input type="password" id="password" name="password" class="form-control" placeholder="Password" required>
        </p>
<p><input type='checkbox' name='remember-me'/> Remember me on this computer.</p>
<input name="${csrfToken.parameterName}" type="hidden" value="${csrfToken.token}" />
        <button class="btn btn-lg btn-primary btn-block" type="submit">Sign in</button>
      </form>
      <form name="oidf" class="form-signin" method="post" action="/login/openid">
        <h2 class="form-signin-heading">Login with OpenID Identity</h2>
        <p>
          <label for="username" class="sr-only">Identity</label>
          <input type="text" id="username" name="openid_identifier" class="form-control" placeholder="Username" required autofocus>
        </p>
<p><input type='checkbox' name='remember-me'/> Remember me on this computer.</p>
<input name="${csrfToken.parameterName}" type="hidden" value="${csrfToken.token}" />
        <button class="btn btn-lg btn-primary btn-block" type="submit">Sign in</button>
      </form>
</div>
</body></html>"""
	}

	@Configuration
	static class DefaultLoginPageWithFormLoginOpenIDRememberMeConfig extends BaseWebConfig {
		@Override
		protected void configure(HttpSecurity http) {
			http
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.rememberMe()
					.and()
				.formLogin()
					.and()
				.openidLogin()
		}
	}

	def "default login with custom AuthenticationEntryPoint"() {
		when:
			loadConfig(DefaultLoginWithCustomAuthenticationEntryPointConfig)
		then:
			!findFilter(DefaultLoginPageGeneratingFilter)
	}

	@Configuration
	static class DefaultLoginWithCustomAuthenticationEntryPointConfig extends BaseWebConfig {
		@Override
		protected void configure(HttpSecurity http) {
			http
				.exceptionHandling()
					.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
					.and()
				.authorizeRequests()
					.anyRequest().hasRole("USER")
					.and()
				.formLogin()
		}
	}

	def "DefaultLoginPage ObjectPostProcessor"() {
		setup:
			AnyObjectPostProcessor objectPostProcessor = Mock()
		when:
			HttpSecurity http = new HttpSecurity(objectPostProcessor, authenticationBldr, [:])
			DefaultLoginPageConfigurer defaultLoginConfig = new DefaultLoginPageConfigurer([builder:http])
			defaultLoginConfig.addObjectPostProcessor(objectPostProcessor)
			http
				// must set builder manually due to groovy not selecting correct method
				.apply(defaultLoginConfig).and()
				.exceptionHandling()
					.and()
				.formLogin()
					.and()
				.build()

		then: "DefaultLoginPageGeneratingFilter is registered with LifecycleManager"
			1 * objectPostProcessor.postProcess(_ as DefaultLoginPageGeneratingFilter) >> {DefaultLoginPageGeneratingFilter o -> o}
			1 * objectPostProcessor.postProcess(_ as UsernamePasswordAuthenticationFilter) >> {UsernamePasswordAuthenticationFilter o -> o}
			1 * objectPostProcessor.postProcess(_ as LoginUrlAuthenticationEntryPoint) >> {LoginUrlAuthenticationEntryPoint o -> o}
			1 * objectPostProcessor.postProcess(_ as ExceptionTranslationFilter) >> {ExceptionTranslationFilter o -> o}
	}
}
