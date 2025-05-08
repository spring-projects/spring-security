CREATE TABLE saml2_asserting_party_metadata
(
    entity_id                 VARCHAR(1000) NOT NULL,
    singlesignon_url          VARCHAR(1000) NOT NULL,
    singlesignon_binding      VARCHAR(100),
    singlesignon_sign_request boolean,
    signing_algorithms        blob,
    verification_credentials  blob          NOT NULL,
    encryption_credentials    blob,
    singlelogout_url          VARCHAR(1000),
    singlelogout_response_url VARCHAR(1000),
    singlelogout_binding      VARCHAR(100),
    PRIMARY KEY (entity_id)
);
