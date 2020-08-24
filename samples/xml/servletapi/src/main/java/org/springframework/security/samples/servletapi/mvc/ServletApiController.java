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

package org.springframework.security.samples.servletapi.mvc;

import java.io.IOException;
import java.security.Principal;

import javax.naming.AuthenticationException;
import javax.servlet.AsyncContext;
import javax.servlet.Servlet;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.stereotype.Controller;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * A Spring MVC Controller that demonstrates Spring Security's integration with the
 * standard Servlet API's. Specifically it demonstrates the following:
 * <ul>
 * <li>{@link #authenticate(HttpServletRequest, HttpServletResponse)} - Integration with
 * {@link HttpServletRequest#authenticate(HttpServletResponse)}</li>
 * <li>{@link #login(HttpServletRequest, HttpServletResponse, LoginForm, BindingResult)} -
 * Integration with {@link HttpServletRequest#login(String, String)}</li>
 * <li>{@link #logout(HttpServletRequest, HttpServletResponse, RedirectAttributes)} - Integration with
 * {@link HttpServletRequest#logout()}</li>
 * <li>{@link #remoteUser(HttpServletRequest)} - Integration with
 * {@link HttpServletRequest#getRemoteUser()}</li>
 * <li>{@link #userPrincipal(HttpServletRequest)} - Integration with
 * {@link HttpServletRequest#getUserPrincipal()}</li>
 * <li>{@link #authentication(Authentication)} - Spring MVC's ability to resolve the
 * {@link Authentication} since it is found on
 * {@link HttpServletRequest#getUserPrincipal()}</li>
 * </ul>
 *
 * @author Rob Winch
 *
 */
@Controller
public class ServletApiController {
	/**
	 * Demonstrates that {@link HttpServletRequest#authenticate(HttpServletResponse)} will
	 * send the user to the log in page configured within Spring Security if the user is
	 * not already authenticated.
	 *
	 * @param request
	 * @param response
	 * @return
	 * @throws ServletException
	 * @throws IOException
	 */
	@RequestMapping("/authenticate")
	public String authenticate(HttpServletRequest request, HttpServletResponse response)
			throws ServletException, IOException {
		boolean authenticate = request.authenticate(response);
		return authenticate ? "index" : null;
	}

	/**
	 * Demonstrates that you can authenticate with Spring Security using
	 * {@link HttpServletRequest#login(String, String)}.
	 *
	 * <p>
	 * If we fail to authenticate, a {@link ServletException} is thrown that wraps the
	 * original {@link AuthenticationException} from Spring Security. This means we can
	 * catch the {@link ServletException} to display the error message. Alternatively, we
	 * could allow the {@link ServletException} to propegate and Spring Security's
	 * {@link ExceptionTranslationFilter} would catch it and process it appropriately.
	 * </p>
	 * <p>
	 * In this method we choose to use Spring MVC's {@link ModelAttribute} to make things
	 * easier for our form. However, this is not necessary. We could have just as easily
	 * obtained the request parameters from the {@link HttpServletRequest} object.
	 * Remember all of these examples would work in a standard {@link Servlet} or anything
	 * with access to the {@link HttpServletRequest} and {@link HttpServletResponse}.
	 * </p>
	 *
	 * @param request
	 * @param response
	 * @param loginForm
	 * @param result
	 * @return
	 */
	@RequestMapping(value = "/login", method = RequestMethod.POST)
	public String login(HttpServletRequest request, HttpServletResponse response,
			@ModelAttribute LoginForm loginForm, BindingResult result) {
		try {
			request.login(loginForm.getUsername(), loginForm.getPassword());
		}
		catch (ServletException authenticationFailed) {
			result.rejectValue(null, "authentication.failed",
					authenticationFailed.getMessage());
			return "login";
		}
		return "redirect:/";
	}

	/**
	 * Demonstrates that invoking {@link HttpServletRequest#logout()} will log the user
	 * out. Note that the response does not get processed, so you need to write something
	 * to the response.
	 * @param request
	 * @param response
	 * @param redirect
	 * @return
	 * @throws ServletException
	 */
	@RequestMapping("/logout")
	public String logout(HttpServletRequest request, HttpServletResponse response,
			RedirectAttributes redirect) throws ServletException {
		request.logout();
		return "redirect:/";
	}

	/**
	 * Demonstrates Spring Security with {@link AsyncContext#start(Runnable)}. Spring
	 * Security will automatically transfer the {@link SecurityContext} from the thread
	 * that {@link AsyncContext#start(Runnable)} is invoked to the new Thread that invokes
	 * the {@link Runnable}.
	 * @param request
	 * @param response
	 */
	@RequestMapping("/async")
	public void asynch(HttpServletRequest request, HttpServletResponse response) {
		final AsyncContext async = request.startAsync();
		async.start(() -> {
			Authentication authentication = SecurityContextHolder.getContext()
					.getAuthentication();
			try {
				final HttpServletResponse asyncResponse = (HttpServletResponse) async
						.getResponse();
				asyncResponse.setStatus(HttpServletResponse.SC_OK);
				asyncResponse.getWriter().write(String.valueOf(authentication));
				async.complete();
			}
			catch (Exception e) {
				throw new RuntimeException(e);
			}
		});
	}

	/**
	 * Demonstrates that Spring Security automatically populates
	 * {@link HttpServletRequest#getRemoteUser()} with the current username.
	 * @param request
	 * @return
	 */
	@ModelAttribute("remoteUser")
	public String remoteUser(HttpServletRequest request) {
		return request.getRemoteUser();
	}

	/**
	 * Demonstrates that Spring Security automatically populates
	 * {@link HttpServletRequest#getUserPrincipal()} with the {@link Authentication} that
	 * is present on {@link SecurityContextHolder#getContext()}
	 * @param request
	 * @return
	 */
	@ModelAttribute("userPrincipal")
	public Principal userPrincipal(HttpServletRequest request) {
		return request.getUserPrincipal();
	}

	/**
	 * Spring MVC will automatically resolve any object that implements {@link Principal}
	 * using {@link HttpServletRequest#getUserPrincipal()}. This means you can easily
	 * resolve the {@link Authentication} just by adding it as an argument to your MVC
	 * controller. Alternatively, you could also have an argument of type
	 * {@link Principal} which would not couple your controller to Spring Security.
	 * @param authentication
	 * @return
	 */
	@ModelAttribute
	public Authentication authentication(Authentication authentication) {
		return authentication;
	}

	@RequestMapping("/")
	public String welcome() {
		return "index";
	}

	@RequestMapping(value = "/login", method = RequestMethod.GET)
	public String login(@ModelAttribute LoginForm loginForm) {
		return "login";
	}
}
