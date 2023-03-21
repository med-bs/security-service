package org.pfe.securityservice.services;

import org.pfe.securityservice.entities.AppRole;
import org.pfe.securityservice.entities.AppUser;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.List;
import java.util.Map;

public interface AccountService {
    AppUser addNewUser(AppUser appUser);
    List<AppUser> allUsers();
    AppUser updateUser(AppUser appUser, String username);
    AppUser findByUserName(String userName);

    AppRole addNewRole(AppRole appRole);
    AppRole findByRoleName(String roleName);
    List<AppRole> allRoles();

    void addRolesToUser(String userName,List<String> roleNames);

    Map<String,String> generateJwtToken(String username, Collection<? extends GrantedAuthority> authorities, boolean withRefreshToken);
}
