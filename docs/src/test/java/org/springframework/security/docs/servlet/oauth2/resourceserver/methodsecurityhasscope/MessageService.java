package org.springframework.security.docs.servlet.oauth2.resourceserver.methodsecurityhasscope;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

@Service
class MessageService {

	// tag::protected-method[]
	@PreAuthorize("@oauth2.hasScope('message:read')")
	String readMessage() {
		return "message";
	}
	// end::protected-method[]
}
