CREATE TABLE saml2_asserting_party_metadata
(
    entity_id                               VARCHAR(1000) NOT NULL,
    single_sign_on_service_location         VARCHAR(1000) NOT NULL,
    single_sign_on_service_binding          VARCHAR(100),
    want_authn_requests_signed              boolean,
    signing_algorithms                      VARCHAR(256) NOT NULL,
    verification_credentials                blob NOT NULL,
    encryption_credentials                  blob,
    single_logout_service_location          VARCHAR(1000),
    single_logout_service_response_location VARCHAR(1000),
    single_logout_service_binding           VARCHAR(100),
    PRIMARY KEY (entity_id)
);
