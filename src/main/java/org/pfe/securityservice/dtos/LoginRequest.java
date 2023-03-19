package org.pfe.securityservice.dtos;


public record LoginRequest(
        String grantType,
        String username,
        String password,
        boolean withRefreshToken,
        String refreshToken
) {
}