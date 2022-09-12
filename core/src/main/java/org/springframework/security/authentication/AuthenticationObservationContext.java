package org.springframework.security.authentication;

import io.micrometer.observation.Observation;

import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;

public class AuthenticationObservationContext extends Observation.Context {

	private Authentication authenticationRequest;

	private Class<?> authenticationManager;

	private Authentication authenticationResult;

	public static AuthenticationObservationContext fromEvent(AuthenticationSuccessEvent event) {
		AuthenticationObservationContext context = new AuthenticationObservationContext();
		context.setName("spring.security." + event.getEventType());
		context.setAuthenticationResult(event.getAuthentication());
		return context;
	}

	public static AuthenticationObservationContext fromEvent(AbstractAuthenticationFailureEvent event) {
		AuthenticationObservationContext context = new AuthenticationObservationContext();
		context.setName("spring.security." + event.getEventType());
		context.setAuthenticationRequest(event.getAuthentication());
		context.setError(event.getException());
		return context;
	}

	public Authentication getAuthenticationRequest() {
		return this.authenticationRequest;
	}

	public void setAuthenticationRequest(Authentication authenticationRequest) {
		this.authenticationRequest = authenticationRequest;
	}

	public Authentication getAuthenticationResult() {
		return authenticationResult;
	}

	public void setAuthenticationResult(Authentication authenticationResult) {
		this.authenticationResult = authenticationResult;
	}

	public Class<?> getAuthenticationManager() {
		return this.authenticationManager;
	}

	public void setAuthenticationManager(Class<?> authenticationManager) {
		this.authenticationManager = authenticationManager;
	}

}
