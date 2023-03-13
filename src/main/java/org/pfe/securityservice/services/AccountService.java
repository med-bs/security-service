package org.pfe.securityservice.services;

import org.pfe.securityservice.entities.AppRole;
import org.pfe.securityservice.entities.AppUser;

public interface AccountService {
    AppUser newUser(AppUser appUser);
    AppUser updateUser(AppUser appUser, Long id);
    AppUser findByUserName(String userName);
    AppRole newRole(AppRole appRole);
    void addRoleToUser(String userName,String roleName);
}
