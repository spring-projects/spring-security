<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<%@ taglib uri="http://www.springframework.org/tags/form" prefix="form" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
<meta http-equiv="content-type" content="text/html; charset=UTF-8">
<link rel="stylesheet" href="/static/css/gae.css" type="text/css" />
<title>Registration</title>
</head>
<body>
<div id="content">
<p>
Welcome to the Spring Security GAE sample application, <sec:authentication property="principal.nickname" />.
Please enter your registration details in order to use the application.
</p>
<p>
The data you enter here will be registered in the application's GAE data store, keyed under your unique
Google Accounts identifier. It doesn't have to be accurate. When you log in again, the information will be automatically
retrieved.
</p>

<form:form id="register" method="post" modelAttribute="registrationForm">
  	<fieldset>
  		<form:label path="forename">
  		Forename:
 		</form:label> <form:errors path="forename" cssClass="fieldError" /><br />
  		<form:input path="forename" /> <br />

  		<form:label path="surname">
  		Surname:
 		</form:label><form:errors path="surname" cssClass="fieldError" /> <br />
  		<form:input path="surname" /><br />
	</fieldset>
	<input type="submit" value="Register">
</form:form>
</body>
</div>
</html>
