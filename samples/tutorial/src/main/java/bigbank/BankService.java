package bigbank;

import org.springframework.security.annotation.Secured;

public interface BankService {
	
	@Secured("IS_AUTHENTICATED_REMEMBERED")
	public Account readAccount(Long id);
		
	@Secured("IS_AUTHENTICATED_REMEMBERED")
	public Account[] findAccounts();
	
	@Secured("ROLE_TELLER")
	public Account post(Account account, double amount);
}
