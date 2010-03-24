<%@ taglib prefix="sec" uri="http://www.springframework.org/security/tags" %>
<html>
<body>
<h1>Authorization Tag Test Page</h1>

<sec:authorize access="hasRole('ROLE_USER')" var="allowed">
Users can see this and 'allowed' variable is ${allowed}.
</sec:authorize>

<sec:authorize access="hasRole('ROLE_X')" var="allowed">
Role X users (nobody) can see this.
</sec:authorize>

Role X expression evaluates to ${allowed}.


</body>

</html>


