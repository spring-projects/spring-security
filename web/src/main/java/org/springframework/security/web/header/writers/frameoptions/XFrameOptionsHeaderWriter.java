/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.web.header.writers.frameoptions;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.web.header.HeaderWriter;
import org.springframework.util.Assert;

/**
 * {@code HeaderWriter} implementation for the X-Frame-Options headers.
 *
 * @author Marten Deinum
 * @author Rob Winch
 * @author Ankur Pathak
 * @since 3.2
 */
public final class XFrameOptionsHeaderWriter implements HeaderWriter {

	public static final String XFRAME_OPTIONS_HEADER = "X-Frame-Options";

	private final XFrameOptionsMode frameOptionsMode;

	/**
	 * Creates an instance with {@link XFrameOptionsMode#DENY}
	 */
	public XFrameOptionsHeaderWriter() {
		this(XFrameOptionsMode.DENY);
	}

	/**
	 * Creates a new instance
	 * @param frameOptionsMode the {@link XFrameOptionsMode} to use. If using
	 */
	public XFrameOptionsHeaderWriter(XFrameOptionsMode frameOptionsMode) {
		Assert.notNull(frameOptionsMode, "frameOptionsMode cannot be null");
		this.frameOptionsMode = frameOptionsMode;
	}

	/**
	 * Writes the X-Frame-Options header value, overwritting any previous value.
	 * @param request the servlet request
	 * @param response the servlet response
	 */
	@Override
	public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
		response.setHeader(XFRAME_OPTIONS_HEADER, this.frameOptionsMode.getMode());
	}

	/**
	 * The possible values for the X-Frame-Options header.
	 *
	 * @author Rob Winch
	 * @since 3.2
	 */
	public enum XFrameOptionsMode {

		DENY("DENY"),

		SAMEORIGIN("SAMEORIGIN");

		private final String mode;

		XFrameOptionsMode(String mode) {
			this.mode = mode;
		}

		/**
		 * Gets the mode for the X-Frame-Options header value. For example, DENY,
		 * SAMEORIGIN. Cannot be null.
		 * @return the mode for the X-Frame-Options header value.
		 */
		private String getMode() {
			return this.mode;
		}

	}

}
