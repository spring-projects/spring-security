/*
 * Copyright 2025 the original author or authors.
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

package org.springframework.security.web.authentication.password;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.password.ChangePasswordAdvice;

public interface ChangePasswordAdviceHandler {

	void handle(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			ChangePasswordAdvice advice) throws ServletException, IOException;

}

// authentication request process
// -------------- ------- -------
// KEEP redirect to home | continue filter | redirect to home
// RESET redirect to home continue filter redirect to home
// REQUIRE_RESET redirect to home redirect to reset redirect to home
