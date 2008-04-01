<%@ taglib prefix='c' uri='http://java.sun.com/jstl/core_rt' %>
<%@ page import="org.springframework.security.ui.AbstractProcessingFilter" %>
<%@ page import="org.springframework.security.ui.webapp.AuthenticationProcessingFilter" %>
<%@ page import="org.springframework.security.AuthenticationException" %>

<!-- Not used unless you declare a <form-login login-page="/login.jsp"/> element -->

<html>
  <head>
    <title>CUSTOM SPRING SECURITY LOGIN</title>
  </head>

  <body onload="document.f.j_username.focus();">
    <h1>CUSTOM SPRING SECURITY LOGIN</h1>

	<P>Valid users:
	<P>
	<P>username <b>rod</b>, password <b>koala</b>
	<br>username <b>dianne</b>, password <b>emu</b>
	<br>username <b>scott</b>, password <b>wombat</b>
	<br>username <b>peter</b>, password <b>opal</b>
	<p>

    <%-- this form-login-page form is also used as the
         form-error-page to ask for a login again.
         --%>
	<% if (session.getAttribute(AbstractProcessingFilter.SPRING_SECURITY_LAST_EXCEPTION_KEY) != null) { %>
      <font color="red">
        Your login attempt was not successful, try again.<BR><BR>
        Reason: <%= ((AuthenticationException) session.getAttribute(AbstractProcessingFilter.SPRING_SECURITY_LAST_EXCEPTION_KEY)).getMessage() %>
      </font>
    <% } %>

    <form name="f" action="<c:url value='j_spring_security_check'/>" method="POST">
      <table>
        <tr><td>User:</td><td><input type='text' name='j_username' <% if (session.getAttribute(AuthenticationProcessingFilter.SPRING_SECURITY_LAST_USERNAME_KEY) != null) { %>value='<%= session.getAttribute(AuthenticationProcessingFilter.SPRING_SECURITY_LAST_USERNAME_KEY) %>'<% } %>></td></tr>
        <tr><td>Password:</td><td><input type='password' name='j_password'></td></tr>
        <tr><td><input type="checkbox" name="_spring_security_remember_me"></td><td>Don't ask for my password for two weeks</td></tr>

        <tr><td colspan='2'><input name="submit" type="submit"></td></tr>
        <tr><td colspan='2'><input name="reset" type="reset"></td></tr>
      </table>

    </form>

  </body>
</html>
