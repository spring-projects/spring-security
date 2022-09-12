package org.springframework.security.authorization;

import java.util.function.Supplier;

import io.micrometer.observation.Observation;

import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.security.authorization.event.AuthorizationGrantedEvent;
import org.springframework.security.core.Authentication;

public class AuthorizationObservationContext<T> extends Observation.Context {

	private Authentication authentication;

	private final T object;

	private AuthorizationDecision decision;

	public AuthorizationObservationContext(T object) {
		this.object = object;
	}

	public static <T> AuthorizationObservationContext<T> fromEvent(AuthorizationGrantedEvent<T> event) {
		Supplier<Authentication> authentication = event.getAuthentication();
		T object = (T) event.getSource();
		AuthorizationObservationContext<T> context = new AuthorizationObservationContext<>(object);
		context.setName("spring.security." + event.getEventType());
		context.setAuthentication(authentication.get());
		context.setDecision(event.getAuthorizationDecision());
		return context;
	}

	public static <T> AuthorizationObservationContext<T> fromEvent(AuthorizationDeniedEvent<T> event) {
		Supplier<Authentication> authentication = event.getAuthentication();
		T object = (T) event.getSource();
		AuthorizationObservationContext<T> context = new AuthorizationObservationContext<>(object);
		context.setName("spring.security." + event.getEventType());
		context.setAuthentication(authentication.get());
		context.setDecision(event.getAuthorizationDecision());
		return context;
	}

	public Authentication getAuthentication() {
		return this.authentication;
	}

	public void setAuthentication(Authentication authentication) {
		this.authentication = authentication;
	}

	public T getObject() {
		return this.object;
	}

	public AuthorizationDecision getDecision() {
		return this.decision;
	}

	public void setDecision(AuthorizationDecision decision) {
		this.decision = decision;
	}

}
