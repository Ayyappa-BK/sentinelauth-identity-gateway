package io.sentinelauth;

import jakarta.validation.constraints.*;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties("sentinel")
public record IdentityProperties(
    @NotBlank String ldapUrl,
    @NotBlank String baseDn,
    @NotBlank String bindDn,
    @NotBlank String bindPassword,
    @NotBlank String realm,
    @NotBlank String servicePrincipal,
    @NotBlank String keytab,
    boolean allowInsecureLdap) {}
