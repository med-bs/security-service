package org.pfe.securityservice.services;

import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Map;

public interface TokenService {
    Map<String,String> generateJwtToken(String username, Collection<? extends GrantedAuthority> authorities, boolean withRefreshToken);
}