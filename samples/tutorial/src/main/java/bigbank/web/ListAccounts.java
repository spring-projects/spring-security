package bigbank.web;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.util.Assert;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.Controller;

import bigbank.BankService;

public class ListAccounts implements Controller {

	private BankService bankService;
	
	public ListAccounts(BankService bankService) {
		Assert.notNull(bankService);
		this.bankService = bankService;
	}

	public ModelAndView handleRequest(HttpServletRequest request, HttpServletResponse response) throws Exception {
		// Security check (this is unnecessary if Spring Security is performing the authorization)
//		if (request.getUserPrincipal() == null) {
//			response.sendError(HttpServletResponse.SC_FORBIDDEN, "You must login to view the account list");
//			return null;
//		}
		
		// Actual business logic
		ModelAndView mav = new ModelAndView("listAccounts");
		mav.addObject("accounts", bankService.findAccounts());
		return mav;
	}

}
