<%@ taglib prefix='c' uri='http://java.sun.com/jstl/core' %>
<html>
  <head>
    <title>Login</title>
  </head>

  <body>
    <h1>Login</h1>

	<P>Valid users:
	<P>
	<P>username <b>marissa</b>, password <b>koala</b>
	<P>username <b>dianne</b>, password <b>emu</b>
	<p>username <b>scott</b>, password <b>wombat</b>
	<p>username <b>peter</b>, password <b>opal</b> (user disabled)
	<p>
	
    <%-- this form-login-page form is also used as the 
         form-error-page to ask for a login again.
         --%>
    <c:if test="${not empty param.login_error}">
      <font color="red">
        Your login attempt was not successful, try again.
      </font>
    </c:if>

    <form action="<c:url value='j_security_check'/>" method="POST">
      <table>
        <tr><td>User:</td><td><input type='text' name='j_username'></td></tr>
        <tr><td>Password:</td><td><input type='password' name='j_password'></td></tr>

        <tr><td colspan='2'><input name="submit" type="submit"></td></tr>
        <tr><td colspan='2'><input name="reset" type="reset"></td></tr>
      </table>

      <!--
        -  The j_uri is a Resin requirement (ignored by other containers)
        -->
      <input type='hidden' name='j_uri' value='/secure/index.htm'/>
    </form>

  </body>
</html>
