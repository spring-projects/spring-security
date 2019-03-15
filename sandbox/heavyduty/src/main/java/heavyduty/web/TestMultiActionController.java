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
package heavyduty.web;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.web.bind.ServletRequestBindingException;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.multiaction.MultiActionController;

/**
 * Reproduces SEC-830.
 */
public class TestMultiActionController extends MultiActionController {
	public static final String VIEW_NAME = "multi-action-test";

	public String login(HttpServletRequest request, HttpServletResponse response) {
		return "login";
	}

	public void step1(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
		String[] x = request.getParameterValues("x");
		logger.info("x= " + (x == null ? "null" : Arrays.asList(x)));
		String[] y = request.getParameterValues("y");
		logger.info("y = " + (y == null ? "null" : Arrays.asList(y)));
		request.getRequestDispatcher("/testMulti.htm?action=step1xtra&x=5&x=5").forward(request, response);
	}

	public ModelAndView step1xtra(HttpServletRequest request, HttpServletResponse response) throws ServletRequestBindingException {
		logger.info("x = " + Arrays.asList(request.getParameterValues("x")));
		return createView("step2");
	}

	public ModelAndView step2(HttpServletRequest request, HttpServletResponse response) throws ServletRequestBindingException {
		return createView("step1");
	}

	private ModelAndView createView(String name) {
		Map<String, String> model = new HashMap<String, String>();
		model.put("nextAction", name);
		return new ModelAndView(VIEW_NAME, model);
	}

}

