<!-- %@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" % -->

<!-- Not used unless you declare a <form-login login-page="/login.jsp"/> element -->

<html>
<head>
  <title>Custom Spring Security Login</title>
</head>

<body>
  <h1>Custom Spring Security Login</h1>

<% 
	if (request.getParameter("login_error") != null) {
%>
      <font color="red">
        Your login attempt was not successful, try again.<br/><br/>
      </font>
<% 
	}
%>

<form action="j_spring_security_check" method="POST">
  <table>
    <tr><td>User:</td><td><input type='text' name='j_username' value=''/></td></tr>
    <tr><td>Password:</td><td><input type='password' name='j_password'></td></tr>
    <tr><td><input type="checkbox" name="_spring_security_remember_me"></td><td>Don't ask for my password for two weeks</td></tr>
    <tr><td colspan='2'><input name="submit" type="submit"></td></tr>
    <tr><td colspan='2'><input name="reset" type="reset"></td></tr>
  </table>
</form>

</body>

</html>
