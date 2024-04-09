/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.config.annotation.method.configuration;

import java.util.List;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * @author Rob Winch
 */
public class MethodSecurityServiceImpl implements MethodSecurityService {

	@Override
	public String preAuthorize() {
		return null;
	}

	@Override
	public String secured() {
		return null;
	}

	@Override
	public String securedUser() {
		return null;
	}

	@Override
	public String jsr250() {
		return null;
	}

	@Override
	public String jsr250PermitAll() {
		return null;
	}

	@Override
	public String jsr250RolesAllowed() {
		return null;
	}

	@Override
	public String jsr250RolesAllowedUser() {
		return null;
	}

	@Override
	public Authentication runAs() {
		return SecurityContextHolder.getContext().getAuthentication();
	}

	@Override
	public void preAuthorizeNotAnonymous() {
	}

	@Override
	public void preAuthorizeBean(boolean b) {
	}

	@Override
	public void preAuthorizeAdmin() {
	}

	@Override
	public void preAuthorizeUser() {
	}

	@Override
	public String preAuthorizePermitAll() {
		return null;
	}

	@Override
	public String hasPermission(String object) {
		return null;
	}

	@Override
	public String postHasPermission(String object) {
		return null;
	}

	@Override
	public String postAnnotation(String object) {
		return null;
	}

	@Override
	public List<String> preFilterByUsername(List<String> array) {
		return array;
	}

	@Override
	public List<String> postFilterByUsername(List<String> array) {
		return array;
	}

	@Override
	public List<String> manyAnnotations(List<String> object) {
		return object;
	}

	@Override
	public List<String> allAnnotations(List<String> list) {
		return null;
	}

	@Override
	public void repeatedAnnotations() {
	}

	@Override
	public String postAuthorizeGetCardNumberIfAdmin(String cardNumber) {
		return cardNumber;
	}

	@Override
	public String preAuthorizeGetCardNumberIfAdmin(String cardNumber) {
		return cardNumber;
	}

	@Override
	public String preAuthorizeWithHandlerChildGetCardNumberIfAdmin(String cardNumber) {
		return cardNumber;
	}

	@Override
	public String preAuthorizeThrowAccessDeniedManually() {
		throw new AuthorizationDeniedException("Access Denied", new AuthorizationDecision(false));
	}

	@Override
	public String postAuthorizeThrowAccessDeniedManually() {
		throw new AuthorizationDeniedException("Access Denied", new AuthorizationDecision(false));
	}

	@Override
	public String preAuthorizeDeniedMethodWithMaskAnnotation() {
		return "ok";
	}

	@Override
	public String preAuthorizeDeniedMethodWithNoMaskAnnotation() {
		return "ok";
	}

	@Override
	public String postAuthorizeDeniedWithNullDenied() {
		return "ok";
	}

	@Override
	public String postAuthorizeDeniedMethodWithMaskAnnotation() {
		return "ok";
	}

	@Override
	public String postAuthorizeDeniedMethodWithNoMaskAnnotation() {
		return "ok";
	}

	@Override
	public String preAuthorizeWithMaskAnnotationUsingBean() {
		return "ok";
	}

	@Override
	public String postAuthorizeWithMaskAnnotationUsingBean() {
		return "ok";
	}

	@Override
	public UserRecordWithEmailProtected getUserRecordWithEmailProtected() {
		return new UserRecordWithEmailProtected("username", "useremail@example.com");
	}

	@Override
	public UserRecordWithEmailProtected getUserWithFallbackWhenUnauthorized() {
		return new UserRecordWithEmailProtected("username", "useremail@example.com");
	}

	@Override
	public String checkCustomResult(boolean result) {
		return "ok";
	}

}
