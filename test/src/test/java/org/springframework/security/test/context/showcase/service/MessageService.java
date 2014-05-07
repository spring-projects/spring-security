package org.springframework.security.test.context.showcase.service;

import org.springframework.security.access.prepost.PreAuthorize;

/**
 * @author Rob Winch
 */
public interface MessageService {
	String getMessage();
}
