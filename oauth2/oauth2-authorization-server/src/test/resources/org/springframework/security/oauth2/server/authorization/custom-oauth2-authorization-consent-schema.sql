CREATE TABLE oauth2AuthorizationConsent (
    registeredClientId varchar(100) NOT NULL,
    principalName varchar(200) NOT NULL,
    authorities varchar(1000) NOT NULL,
    PRIMARY KEY (registeredClientId, principalName)
);
