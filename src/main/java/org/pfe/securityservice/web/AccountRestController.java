package org.pfe.securityservice.web;

import org.pfe.securityservice.dtos.RoleUserDTO;
import org.pfe.securityservice.entities.AppRole;
import org.pfe.securityservice.entities.AppUser;
import org.pfe.securityservice.services.AccountService;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
public class AccountRestController {

    private final AccountService accountService;

    public AccountRestController(AccountService accountService) {
        this.accountService = accountService;
    }

    @GetMapping("/user")
    public List<AppUser> AllAppUsers(){
        return accountService.allUsers();
    }

    @GetMapping("/users/{username}")
    public AppUser findAppUser(@PathVariable String username){
        return accountService.findByUserName(username);
    }

    @PostMapping("/user")
    public AppUser saveAppUser(@RequestBody AppUser appUser){
        return accountService.addNewUser(appUser);
    }

    @PutMapping("/users/{id}")
    public AppUser updateAppUser(@PathVariable Long id, @RequestBody AppUser appUser){
        return accountService.updateUser(appUser,id);
    }

    @GetMapping("/role")
    public List<AppRole> allAppRoles(){
        return accountService.allRoles();
    }

    @PostMapping("/role")
    public AppRole saveNewRole(@RequestBody AppRole appRole){
        return accountService.addNewRole(appRole);
    }

    @PostMapping("/addroletouser")
    public void addRoleToUser(@RequestBody RoleUserDTO roleUserDTO){
        accountService.addRoleToUser(roleUserDTO.getUsername(), roleUserDTO.getRoleName());
    }
}
