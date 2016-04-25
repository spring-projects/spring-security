package org.springframework.security.web.csrf;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.util.ReflectionUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.lang.reflect.Method;

import static org.mockito.Matchers.eq;
import static org.mockito.Matchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.*;
import static org.powermock.api.mockito.PowerMockito.spy;
import static org.powermock.api.mockito.PowerMockito.*;
import static org.powermock.api.mockito.PowerMockito.when;

/**
 * @author Joe Grandja
 * @since 4.1
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ReflectionUtils.class, Method.class})
public class CookieCsrfTokenRepositoryServlet3Tests {

	@Mock
	private Method method;

	@Test
	public void httpOnlyServlet30() throws Exception {
		spy(ReflectionUtils.class);
		when(ReflectionUtils.findMethod(Cookie.class, "setHttpOnly",
				boolean.class)).thenReturn(method);

		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getContextPath()).thenReturn("/contextpath");
		HttpServletResponse response = mock(HttpServletResponse.class);
		ArgumentCaptor<Cookie> cookie = ArgumentCaptor.forClass(Cookie.class);

		CookieCsrfTokenRepository repository = new CookieCsrfTokenRepository();

		CsrfToken token = repository.generateToken(request);
		repository.saveToken(token, request, response);

		verify(response).addCookie(cookie.capture());
		verifyStatic();
		ReflectionUtils.invokeMethod(same(method), eq(cookie.getValue()), eq(true));
	}

	@Test
	public void httpOnlyPreServlet30() throws Exception {
		spy(ReflectionUtils.class);
		when(ReflectionUtils.findMethod(Cookie.class, "setHttpOnly",
				boolean.class)).thenReturn(null);

		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getContextPath()).thenReturn("/contextpath");
		HttpServletResponse response = mock(HttpServletResponse.class);
		ArgumentCaptor<Cookie> cookie = ArgumentCaptor.forClass(Cookie.class);

		CookieCsrfTokenRepository repository = new CookieCsrfTokenRepository();

		CsrfToken token = repository.generateToken(request);
		repository.saveToken(token, request, response);

		verify(response).addCookie(cookie.capture());
		verifyStatic(never());
		ReflectionUtils.invokeMethod(same(method), eq(cookie.getValue()), eq(true));
	}

}