package org.pfe.securityservice.web;

import org.pfe.securityservice.dtos.LoginDTO;
import org.pfe.securityservice.dtos.RoleUserDTO;
import org.pfe.securityservice.dtos.SignupDTO;
import org.pfe.securityservice.entities.AppRole;
import org.pfe.securityservice.entities.AppUser;
import org.pfe.securityservice.services.AccountService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.web.bind.annotation.*;

import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@RestController
@RequestMapping("/api/v2")
public class AuthController {
    private final AccountService accountService;
    private final JwtDecoder jwtDecoder;
    private final PasswordEncoder passwordEncoder;

    private AuthenticationManager authenticationManager;

    public AuthController(AccountService accountService, JwtDecoder jwtDecoder, PasswordEncoder passwordEncoder, AuthenticationManager authenticationManager) {
        this.accountService = accountService;
        this.jwtDecoder = jwtDecoder;
        this.passwordEncoder = passwordEncoder;
        this.authenticationManager = authenticationManager;
    }

    @PostMapping("/login")
    public ResponseEntity<Map<String, String>> requestForTokenLogIn(@RequestBody LoginDTO loginDTO) {
        Map<String, String> response;

        if (loginDTO.grantType().equals("password")) {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginDTO.username(), loginDTO.password()
                    )
            );
            response = accountService.generateJwtToken(authentication.getName(), authentication.getAuthorities(), loginDTO.withRefreshToken());
            return ResponseEntity.ok(response);

        } else if (loginDTO.grantType().equals("refreshToken")) {
            String refreshToken = loginDTO.refreshToken();
            if (refreshToken == null) {
                return new ResponseEntity<>(Map.of("error", "RefreshToken Not Present"), HttpStatus.UNAUTHORIZED);
            }
            Jwt decodedJwt = jwtDecoder.decode(refreshToken);
            String username = decodedJwt.getSubject();
            AppUser appUser = accountService.findByUserName(username);
            Collection<GrantedAuthority> authorities = appUser.getAppRoles()
                    .stream()
                    .map(role -> new SimpleGrantedAuthority(role.getRoleName()))
                    .collect(Collectors.toList());
            response = accountService.generateJwtToken(appUser.getUsername(), authorities, loginDTO.withRefreshToken());
            return ResponseEntity.ok(response);
        }

        return new ResponseEntity<>(Map.of("error", String.format("grantType <<%s>> not supported ", loginDTO.grantType())), HttpStatus.UNAUTHORIZED);
    }

    @PostMapping("/signup")
    public ResponseEntity<Map<String, String>> requestForTokenSignUp(@RequestBody SignupDTO signupDTO) {
        Map<String, String> response;
        try {
            accountService.addNewUser(AppUser.builder().username(signupDTO.username())
                    .password(passwordEncoder.encode(signupDTO.password()))
                    .appRoles(List.of(accountService.findByRoleName("USER")))
                    .build());
        } catch (Exception e) {
            return new ResponseEntity<>(Map.of("error", e.getMessage()), HttpStatus.BAD_REQUEST);
        }

        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        signupDTO.username(), signupDTO.password()
                )
        );

        response = accountService.generateJwtToken(authentication.getName(), authentication.getAuthorities(), false);
        return new ResponseEntity<>(response,HttpStatus.CREATED);
    }

    @GetMapping("/users")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public ResponseEntity<List<AppUser>> AllAppUsers(){
        return ResponseEntity.ok(accountService.allUsers());
    }

    @GetMapping("/users/{username}")
    @PreAuthorize("hasAuthority('SCOPE_USER')")
    public ResponseEntity findAppUser(@RequestHeader("Authorization") String bearerToken, @PathVariable String username){
        String token;
        if (bearerToken.startsWith("Bearer ")) {
            token = bearerToken.substring(7);
            Jwt tokenDecoded = jwtDecoder.decode(token);
            if(tokenDecoded.getSubject().equals(username) || tokenDecoded.getClaim("scope").toString().contains("ADMIN")){
                return ResponseEntity.ok(accountService.findByUserName(username));
            }
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    @PutMapping("/users/{username}")
    @PreAuthorize("hasAuthority('SCOPE_USER')")
    public ResponseEntity updateAppUser(@RequestHeader("Authorization") String bearerToken, @PathVariable String username, @RequestBody AppUser appUser){
        String token;
        if (bearerToken.startsWith("Bearer ")) {
            token = bearerToken.substring(7);
            Jwt tokenDecoded = jwtDecoder.decode(token);
            if(tokenDecoded.getSubject().equals(username) || tokenDecoded.getClaim("scope").toString().contains("ADMIN")){
                appUser.setPassword(passwordEncoder.encode(appUser.getPassword()));
                return ResponseEntity.ok(accountService.updateUser(appUser,username));
            }
        }
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
    }

    @GetMapping("/role")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public ResponseEntity<List<AppRole>> allAppRoles(){
        return ResponseEntity.ok(accountService.allRoles());
    }

    @PostMapping("/addroletouser")
    @PreAuthorize("hasAuthority('SCOPE_ADMIN')")
    public ResponseEntity addRoleToUser(@RequestBody RoleUserDTO roleUserDTO) {
        accountService.addRolesToUser(roleUserDTO.getUsername(), roleUserDTO.getRoleNames());
        return ResponseEntity.ok("role added");
    }
}