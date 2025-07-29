package org.springframework.security.web.authentication.password;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.password.ChangePasswordAdvice;
import org.springframework.security.authentication.password.ChangePasswordAdvisor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;
import org.springframework.util.Assert;

public final class ChangePasswordAdviceSessionAuthenticationStrategy implements SessionAuthenticationStrategy {

	private ChangePasswordAdviceRepository changePasswordAdviceRepository = new HttpSessionChangePasswordAdviceRepository();

	private ChangePasswordAdvisor changePasswordAdvisor = new ChangeCompromisedPasswordAdvisor();

	private final String passwordParameter;

	public ChangePasswordAdviceSessionAuthenticationStrategy(String passwordParameter) {
		this.passwordParameter = passwordParameter;
	}

	@Override
	public void onAuthentication(Authentication authentication, HttpServletRequest request,
			HttpServletResponse response) throws SessionAuthenticationException {
		UserDetails user = (UserDetails) authentication.getPrincipal();
		Assert.notNull(user, "cannot persist password advice since user principal is null");
		String password = request.getParameter(this.passwordParameter);
		ChangePasswordAdvice advice = this.changePasswordAdvisor.advise(user, password);
		this.changePasswordAdviceRepository.savePasswordAdvice(request, response, advice);
	}

	public void setChangePasswordAdviceRepository(ChangePasswordAdviceRepository changePasswordAdviceRepository) {
		this.changePasswordAdviceRepository = changePasswordAdviceRepository;
	}

	public void setChangePasswordAdvisor(ChangePasswordAdvisor changePasswordAdvisor) {
		this.changePasswordAdvisor = changePasswordAdvisor;
	}

}
