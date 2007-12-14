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

	private BankService bankService;
	
	public PostAccounts(BankService bankService) {
		Assert.notNull(bankService);
		this.bankService = bankService;
	}

	public ModelAndView handleRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
		// Security check (this is unnecessary if Spring Security is performing the authorization)
//		if (request.isUserInRole("ROLE_TELLER")) {
//			response.sendError(HttpServletResponse.SC_FORBIDDEN, "You must be a teller to post transactions");
//			return null;
//		}
		
		// Actual business logic
		Long id = ServletRequestUtils.getRequiredLongParameter(request, "id");
		Double amount = ServletRequestUtils.getRequiredDoubleParameter(request, "amount");
		Account a = bankService.readAccount(id);
		bankService.post(a, amount);
		
		return new ModelAndView("redirect:listAccounts.html");
	}

}
