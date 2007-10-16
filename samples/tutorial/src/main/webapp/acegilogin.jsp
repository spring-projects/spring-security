<%@ taglib prefix='c' uri='http://java.sun.com/jstl/core' %>
<%@ page import="org.springframework.security.ui.AbstractProcessingFilter" %>
<%@ page import="org.springframework.security.ui.webapp.AuthenticationProcessingFilter" %>
<%@ page import="org.springframework.security.AuthenticationException" %>

<html>
  <head>
    <title>Login</title>
  </head>

  <body>
    <h1>Login</h1>

	<P>Valid users:
	<P>
	<P>username <b>marissa</b>, password <b>koala</b> (supervisor)
	<P>username <b>dianne</b>, password <b>emu</b> (normal user)
	<p>username <b>scott</b>, password <b>wombat</b> (normal user)
	<p>username <b>peter</b>, password <b>opal</b> (user disabled)
	<p>

    <%-- this form-login-page form is also used as the
         form-error-page to ask for a login again.
         --%>
    <c:if test="${not empty param.login_error}">
      <font color="red">
        Your login attempt was not successful, try again.<BR><BR>
        Reason: <%= ((AuthenticationException) session.getAttribute(AbstractProcessingFilter.SPRING_SECURITY_LAST_EXCEPTION_KEY)).getMessage() %>
      </font>
    </c:if>

    <form action="<c:url value='j_spring_security_check'/>" method="POST">
      <table>
        <tr><td>User:</td><td><input type='text' name='j_username' <c:if test="${not empty param.login_error}">value='<c:out value="${ACEGI_SECURITY_LAST_USERNAME}"/>'</c:if>></td></tr>
        <tr><td>Password:</td><td><input type='password' name='j_password'></td></tr>
        <tr><td><input type="checkbox" name="_spring_security_remember_me"></td><td>Don't ask for my password for two weeks</td></tr>

        <tr><td colspan='2'><input name="submit" type="submit"></td></tr>
        <tr><td colspan='2'><input name="reset" type="reset"></td></tr>
      </table>

    </form>

  </body>
</html>
