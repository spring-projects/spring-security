package org.springframework.security.web.access;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;

import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

@ExtendWith(MockitoExtension.class)
public class HttpStatusAccessDeniedHandlerTests {

	@Mock
	private HttpServletRequest request;

	@Mock
	private HttpServletResponse response;

	private HttpStatus httpStatus = HttpStatus.FORBIDDEN;

	private HttpStatusAccessDeniedHandler handler = new HttpStatusAccessDeniedHandler(this.httpStatus);

	private AccessDeniedException exception = new AccessDeniedException("Forbidden");

	@Test
	public void constructorHttpStatusWhenNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new HttpStatusAccessDeniedHandler(null));
	}

	@Test
	public void commenceThenStatusSet() throws IOException, ServletException {
		this.response = new MockHttpServletResponse();
		this.handler.handle(this.request, this.response, this.exception);
		assertThat(this.response.getStatus()).isEqualTo(this.httpStatus.value());
	}

}
