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
package samples.gae.web;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.google.appengine.api.users.UserServiceFactory;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

/**
 *
 * @author Luke Taylor
 *
 */
@Controller
public class GaeAppController {

	@RequestMapping(value = "/", method = RequestMethod.GET)
	public String landing() {
		return "landing";
	}

	@RequestMapping(value = "/home.htm", method = RequestMethod.GET)
	public String home() {
		return "home";
	}

	@RequestMapping(value = "/disabled.htm", method = RequestMethod.GET)
	public String disabled() {
		return "disabled";
	}

	@RequestMapping(value = "/logout.htm", method = RequestMethod.GET)
	public void logout(HttpServletRequest request, HttpServletResponse response)
			throws IOException {
		request.getSession().invalidate();

		String logoutUrl = UserServiceFactory.getUserService().createLogoutURL(
				"/loggedout.htm");

		response.sendRedirect(logoutUrl);
	}

	@RequestMapping(value = "/loggedout.htm", method = RequestMethod.GET)
	public String loggedOut() {
		return "loggedout";
	}
}
