package org.pfe.securityservice.services;

import org.pfe.securityservice.entities.AppRole;
import org.pfe.securityservice.entities.AppUser;
import org.pfe.securityservice.repositories.AppRoleRepository;
import org.pfe.securityservice.repositories.AppUserRepository;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;


@Service
@Transactional
public class AccountServiceImpl implements AccountService{

    private final AppUserRepository appUserRepository;
    private final AppRoleRepository appRoleRepository;
    private final JwtEncoder jwtEncoder;

    public AccountServiceImpl(AppUserRepository appUserRepository, AppRoleRepository appRoleRepository, JwtEncoder jwtEncoder) {
        this.appUserRepository = appUserRepository;
        this.appRoleRepository = appRoleRepository;
        this.jwtEncoder = jwtEncoder;
    }

    @Override
    public AppUser addNewUser(AppUser appUser){
        return appUserRepository.save(appUser);
    }

    @Override
    public List<AppUser> allUsers(){
        return appUserRepository.findAll();
    }

    @Override
    public AppUser updateUser(AppUser appUser,String username){
        appUser.setUsername(username);
        return appUserRepository.save(appUser);
    }

    @Override
    public AppUser findByUserName(String userName) {
        return appUserRepository.findByUsername(userName);
    }

    @Override
    public AppRole addNewRole(AppRole appRole) {
        return appRoleRepository.save(appRole);
    }

    @Override
    public List<AppRole> allRoles(){
        return appRoleRepository.findAll();
    }

    @Override
    public AppRole findByRoleName(String roleName){
        return appRoleRepository.findByRoleName(roleName);
    }

    @Override
    public void addRolesToUser(String userName,List<String> roleNames){
        AppUser appUser=appUserRepository.findByUsername(userName);
        List<AppRole> appRoles = roleNames.stream().map(appRoleRepository::findByRoleName).toList();
        appUser.getAppRoles().addAll(appRoles);
    }

    public Map<String,String> generateJwtToken(String username, Collection<? extends GrantedAuthority> authorities, boolean withRefreshToken){
        Map<String,String> idToken=new HashMap<>();
        Instant instant=Instant.now();
        String scope=authorities.stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(" "));
        JwtClaimsSet jwtClaimsSet=JwtClaimsSet.builder()
                .issuer("auth-service")
                .issuedAt(instant)
                .expiresAt(instant.plus(withRefreshToken?5:30, ChronoUnit.MINUTES))
                .subject(username)
                .claim("scope",scope)
                .build();
        String accessToken = this.jwtEncoder.encode(JwtEncoderParameters.from(jwtClaimsSet)).getTokenValue();
        idToken.put("accessToken",accessToken);
        if(withRefreshToken){
            JwtClaimsSet jwtRefreshTokenClaimsSet=JwtClaimsSet.builder()
                    .issuer("auth-service")
                    .issuedAt(instant)
                    .expiresAt(instant.plus(10, ChronoUnit.MINUTES))
                    .subject(username)
                    .build();
            String refreshToken = this.jwtEncoder.encode(JwtEncoderParameters.from(jwtRefreshTokenClaimsSet)).getTokenValue();
            idToken.put("refreshToken",refreshToken);
        }
        return idToken;
    }
}
