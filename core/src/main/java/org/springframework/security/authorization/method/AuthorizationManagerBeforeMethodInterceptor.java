/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.authorization.method;

import java.util.function.Supplier;

import jakarta.annotation.security.DenyAll;
import jakarta.annotation.security.PermitAll;
import jakarta.annotation.security.RolesAllowed;
import org.aopalliance.aop.Advice;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.aop.Pointcut;
import org.springframework.aop.PointcutAdvisor;
import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.core.Ordered;
import org.springframework.core.log.LogMessage;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;

/**
 * A {@link MethodInterceptor} which uses a {@link AuthorizationManager} to determine if
 * an {@link Authentication} may invoke the given {@link MethodInvocation}
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @since 5.6
 */
public final class AuthorizationManagerBeforeMethodInterceptor
		implements Ordered, MethodInterceptor, PointcutAdvisor, AopInfrastructureBean {

	private Supplier<Authentication> authentication = getAuthentication(
			SecurityContextHolder.getContextHolderStrategy());

	private final Log logger = LogFactory.getLog(this.getClass());

	private final Pointcut pointcut;

	private final AuthorizationManager<MethodInvocation> authorizationManager;

	private int order = AuthorizationInterceptorsOrder.FIRST.getOrder();

	private AuthorizationEventPublisher eventPublisher = AuthorizationManagerBeforeMethodInterceptor::noPublish;

	/**
	 * Creates an instance.
	 * @param pointcut the {@link Pointcut} to use
	 * @param authorizationManager the {@link AuthorizationManager} to use
	 */
	public AuthorizationManagerBeforeMethodInterceptor(Pointcut pointcut,
			AuthorizationManager<MethodInvocation> authorizationManager) {
		Assert.notNull(pointcut, "pointcut cannot be null");
		Assert.notNull(authorizationManager, "authorizationManager cannot be null");
		this.pointcut = pointcut;
		this.authorizationManager = authorizationManager;
	}

	/**
	 * Creates an interceptor for the {@link PreAuthorize} annotation
	 * @return the interceptor
	 */
	public static AuthorizationManagerBeforeMethodInterceptor preAuthorize() {
		return preAuthorize(new PreAuthorizeAuthorizationManager());
	}

	/**
	 * Creates an interceptor for the {@link PreAuthorize} annotation
	 * @param authorizationManager the {@link PreAuthorizeAuthorizationManager} to use
	 * @return the interceptor
	 */
	public static AuthorizationManagerBeforeMethodInterceptor preAuthorize(
			PreAuthorizeAuthorizationManager authorizationManager) {
		AuthorizationManagerBeforeMethodInterceptor interceptor = new AuthorizationManagerBeforeMethodInterceptor(
				AuthorizationMethodPointcuts.forAnnotations(PreAuthorize.class), authorizationManager);
		interceptor.setOrder(AuthorizationInterceptorsOrder.PRE_AUTHORIZE.getOrder());
		return interceptor;
	}

	/**
	 * Creates an interceptor for the {@link PreAuthorize} annotation
	 * @param authorizationManager the {@link AuthorizationManager} to use
	 * @return the interceptor
	 * @since 6.0
	 */
	public static AuthorizationManagerBeforeMethodInterceptor preAuthorize(
			AuthorizationManager<MethodInvocation> authorizationManager) {
		AuthorizationManagerBeforeMethodInterceptor interceptor = new AuthorizationManagerBeforeMethodInterceptor(
				AuthorizationMethodPointcuts.forAnnotations(PreAuthorize.class), authorizationManager);
		interceptor.setOrder(AuthorizationInterceptorsOrder.PRE_AUTHORIZE.getOrder());
		return interceptor;
	}

	/**
	 * Creates an interceptor for the {@link Secured} annotation
	 * @return the interceptor
	 */
	public static AuthorizationManagerBeforeMethodInterceptor secured() {
		return secured(new SecuredAuthorizationManager());
	}

	/**
	 * Creates an interceptor for the {@link Secured} annotation
	 * @param authorizationManager the {@link SecuredAuthorizationManager} to use
	 * @return the interceptor
	 */
	public static AuthorizationManagerBeforeMethodInterceptor secured(
			SecuredAuthorizationManager authorizationManager) {
		AuthorizationManagerBeforeMethodInterceptor interceptor = new AuthorizationManagerBeforeMethodInterceptor(
				AuthorizationMethodPointcuts.forAnnotations(Secured.class), authorizationManager);
		interceptor.setOrder(AuthorizationInterceptorsOrder.SECURED.getOrder());
		return interceptor;
	}

	/**
	 * Creates an interceptor for the {@link Secured} annotation
	 * @param authorizationManager the {@link AuthorizationManager} to use
	 * @return the interceptor
	 * @since 6.0
	 */
	public static AuthorizationManagerBeforeMethodInterceptor secured(
			AuthorizationManager<MethodInvocation> authorizationManager) {
		AuthorizationManagerBeforeMethodInterceptor interceptor = new AuthorizationManagerBeforeMethodInterceptor(
				AuthorizationMethodPointcuts.forAnnotations(Secured.class), authorizationManager);
		interceptor.setOrder(AuthorizationInterceptorsOrder.SECURED.getOrder());
		return interceptor;
	}

	/**
	 * Creates an interceptor for the JSR-250 annotations
	 * @return the interceptor
	 */
	public static AuthorizationManagerBeforeMethodInterceptor jsr250() {
		return jsr250(new Jsr250AuthorizationManager());
	}

	/**
	 * Creates an interceptor for the JSR-250 annotations
	 * @param authorizationManager the {@link Jsr250AuthorizationManager} to use
	 * @return the interceptor
	 */
	public static AuthorizationManagerBeforeMethodInterceptor jsr250(Jsr250AuthorizationManager authorizationManager) {
		AuthorizationManagerBeforeMethodInterceptor interceptor = new AuthorizationManagerBeforeMethodInterceptor(
				AuthorizationMethodPointcuts.forAnnotations(RolesAllowed.class, DenyAll.class, PermitAll.class),
				authorizationManager);
		interceptor.setOrder(AuthorizationInterceptorsOrder.JSR250.getOrder());
		return interceptor;
	}

	/**
	 * Creates an interceptor for the JSR-250 annotations
	 * @param authorizationManager the {@link AuthorizationManager} to use
	 * @return the interceptor
	 * @since 6.0
	 */
	public static AuthorizationManagerBeforeMethodInterceptor jsr250(
			AuthorizationManager<MethodInvocation> authorizationManager) {
		AuthorizationManagerBeforeMethodInterceptor interceptor = new AuthorizationManagerBeforeMethodInterceptor(
				AuthorizationMethodPointcuts.forAnnotations(RolesAllowed.class, DenyAll.class, PermitAll.class),
				authorizationManager);
		interceptor.setOrder(AuthorizationInterceptorsOrder.JSR250.getOrder());
		return interceptor;
	}

	/**
	 * Determine if an {@link Authentication} has access to the {@link MethodInvocation}
	 * using the configured {@link AuthorizationManager}.
	 * @param mi the {@link MethodInvocation} to check
	 * @throws AccessDeniedException if access is not granted
	 */
	@Override
	public Object invoke(MethodInvocation mi) throws Throwable {
		attemptAuthorization(mi);
		return mi.proceed();
	}

	@Override
	public int getOrder() {
		return this.order;
	}

	public void setOrder(int order) {
		this.order = order;
	}

	/**
	 * Use this {@link AuthorizationEventPublisher} to publish the
	 * {@link AuthorizationManager} result.
	 * @param eventPublisher
	 * @since 5.7
	 */
	public void setAuthorizationEventPublisher(AuthorizationEventPublisher eventPublisher) {
		Assert.notNull(eventPublisher, "eventPublisher cannot be null");
		this.eventPublisher = eventPublisher;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Pointcut getPointcut() {
		return this.pointcut;
	}

	@Override
	public Advice getAdvice() {
		return this;
	}

	@Override
	public boolean isPerInstance() {
		return true;
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
	 * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
	 *
	 * @since 5.8
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		this.authentication = getAuthentication(securityContextHolderStrategy);
	}

	private void attemptAuthorization(MethodInvocation mi) {
		this.logger.debug(LogMessage.of(() -> "Authorizing method invocation " + mi));
		AuthorizationDecision decision = this.authorizationManager.check(this.authentication, mi);
		this.eventPublisher.publishAuthorizationEvent(this.authentication, mi, decision);
		if (decision != null && !decision.isGranted()) {
			this.logger.debug(LogMessage.of(() -> "Failed to authorize " + mi + " with authorization manager "
					+ this.authorizationManager + " and decision " + decision));
			throw new AccessDeniedException("Access Denied");
		}
		this.logger.debug(LogMessage.of(() -> "Authorized method invocation " + mi));
	}

	private Supplier<Authentication> getAuthentication(SecurityContextHolderStrategy strategy) {
		return () -> {
			Authentication authentication = strategy.getContext().getAuthentication();
			if (authentication == null) {
				throw new AuthenticationCredentialsNotFoundException(
						"An Authentication object was not found in the SecurityContext");
			}
			return authentication;
		};
	}

	private static <T> void noPublish(Supplier<Authentication> authentication, T object,
			AuthorizationDecision decision) {

	}

}
