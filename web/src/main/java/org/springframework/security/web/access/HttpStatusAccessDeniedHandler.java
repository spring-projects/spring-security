package org.springframework.security.web.access;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.log.LogMessage;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.util.Assert;

import java.io.IOException;

public class HttpStatusAccessDeniedHandler implements AccessDeniedHandler {

	protected static final Log logger = LogFactory.getLog(HttpStatusAccessDeniedHandler.class);

	private final HttpStatus httpStatus;

	public HttpStatusAccessDeniedHandler(HttpStatus httpStatus) {
		Assert.notNull(httpStatus, "httpStatus cannot be null");
		this.httpStatus = httpStatus;
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException, ServletException {
		logger.debug(LogMessage.format("Access denied with status code %d", this.httpStatus.value()));

		response.sendError(this.httpStatus.value(),  "Access Denied");
	}

}
