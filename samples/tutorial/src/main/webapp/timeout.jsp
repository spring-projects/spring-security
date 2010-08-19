<%@page session="false" %>
<%@taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core" %>

<html>
<head>
<title>Session Timeout</title>
</head>
<body>
<h2>Invalid Session</h2>

<p>
Your session appears to have timed out. Please <a href="<c:url value='/'/>">start again</a>.
</p>
</body>
</html>
