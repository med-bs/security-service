package org.pfe.securityservice.services;

import org.pfe.securityservice.entities.AppRole;
import org.pfe.securityservice.entities.AppUser;
import org.pfe.securityservice.repositories.AppRoleRepository;
import org.pfe.securityservice.repositories.AppUserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;


@Service
@Transactional
public class AccountServiceImpl implements AccountService{

    private final AppUserRepository appUserRepository;
    private final AppRoleRepository appRoleRepository;

    public AccountServiceImpl(AppUserRepository appUserRepository, AppRoleRepository appRoleRepository) {
        this.appUserRepository = appUserRepository;
        this.appRoleRepository = appRoleRepository;
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
    public AppUser updateUser(AppUser appUser,Long id){
        appUser.setId(id);
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
    public void addRoleToUser(String userName,String roleName){
        AppUser appUser=appUserRepository.findByUsername(userName);
        AppRole appRole=appRoleRepository.findByRoleName(roleName);
        appUser.getAppRoles().add(appRole);
    }
}
