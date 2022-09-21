package org.springframework.security.web;

public interface DefenseEventPublisher {
	void publishCsrfTokenMismatched();

}
