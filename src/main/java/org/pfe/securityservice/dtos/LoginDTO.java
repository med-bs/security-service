package org.pfe.securityservice.dtos;


public record LoginDTO(
        String grantType,
        String username,
        String password,
        boolean withRefreshToken,
        String refreshToken
) {
}