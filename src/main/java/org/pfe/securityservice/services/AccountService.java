package org.pfe.securityservice.services;

import org.pfe.securityservice.entities.AppRole;
import org.pfe.securityservice.entities.AppUser;

import java.util.List;

public interface AccountService {
    AppUser addNewUser(AppUser appUser);
    List<AppUser> allUsers();
    AppUser updateUser(AppUser appUser, Long id);
    AppUser findByUserName(String userName);
    AppRole addNewRole(AppRole appRole);
    List<AppRole> allRoles();
    void addRoleToUser(String userName,String roleName);
}
