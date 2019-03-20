<%@taglib prefix="c" uri="https://java.sun.com/jsp/jstl/core" %>
<%@ taglib prefix="security" uri="http://www.springframework.org/security/tags" %>

<html>
<body>
<h1>VERY Secure Page</h1>
This is a protected page. You can only see me if you are a supervisor.

<p><a href="../../">Home</a>
<form action="<c:url value="/logout"/>" method="post">
<input type="submit" value="Logoff"/>
<security:csrfInput/>
</form>
</body>
</html>