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
package bigbank.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.util.Assert;
import org.springframework.web.bind.ServletRequestUtils;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.Controller;

import bigbank.Account;
import bigbank.BankService;

public class PostAccounts implements Controller {

	private final BankService bankService;

	public PostAccounts(BankService bankService) {
		Assert.notNull(bankService, "bankService cannot be null");
		this.bankService = bankService;
	}

	public ModelAndView handleRequest(HttpServletRequest request,
			HttpServletResponse response) throws Exception {
		// Security check (this is unnecessary if Spring Security is performing the
		// authorization)
		// if (!request.isUserInRole("ROLE_TELLER")) {
		// throw new
		// AccessDeniedException("You must be a teller to post transactions (Spring Security message)");
		// }

		// Actual business logic
		Long id = ServletRequestUtils.getRequiredLongParameter(request, "id");
		Double amount = ServletRequestUtils.getRequiredDoubleParameter(request, "amount");
		Account a = bankService.readAccount(id);
		bankService.post(a, amount);

		return new ModelAndView("redirect:listAccounts.html");
	}

}
