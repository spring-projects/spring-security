<%@ include file="/WEB-INF/jsp/include.jsp" %>

<html>
<head><title>Deletion completed</title></head>
<body>
<h1>Deleted</h1>
<P>
<code>
<c:out value="${contact}"/>
</code>
<p><a href="<c:url value="index.htm"/>">Manage</a>
</body>
</html>
