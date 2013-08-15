<%@ taglib prefix='c' uri='http://java.sun.com/jstl/core' %>
<%@ page import="org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter" %>
<%@ page import="org.springframework.security.core.AuthenticationException" %>
<%@ page pageEncoding="UTF-8" %>

<html>
  <head>
    <title>Switch User</title>
  </head>

  <body>
    <h1>Switch to User</h1>

	<h3>Valid users:</h3>

	<p>username <b>rod</b>, password <b>koala</b></p>
	<p>username <b>dianne</b>, password <b>emu</b></p>
	<p>username <b>scott</b>, password <b>wombat</b></p>
	<p>username <b>bill</b>, password <b>wombat</b></p>
	<p>username <b>bob</b>, password <b>wombat</b></p>
	<p>username <b>jane</b>, password <b>wombat</b></p>
    <%-- this form-login-page form is also used as the
         form-error-page to ask for a login again.
         --%>
    <c:if test="${not empty param.login_error}">
    <p>
      <font color="red">
        Your 'su' attempt was not successful, try again.<br/><br/>
        Reason: <%= ((AuthenticationException) session.getAttribute(AbstractAuthenticationProcessingFilter.SPRING_SECURITY_LAST_EXCEPTION_KEY)).getMessage() %>
      </font>
          </p>
    </c:if>

    <form action="<c:url value='j_spring_security_switch_user'/>" method="POST">
      <table>
        <tr><td>User:</td><td><input type='text' name='j_username'></td></tr>
        <tr><td colspan='2'><input name="switch" type="submit" value="Switch to User"></td></tr>
      </table>
      <input type="hidden" name="<c:out value="${_csrf.parameterName}"/>" value="<c:out value="${_csrf.token}"/>"/>
    </form>

  </body>
</html>
