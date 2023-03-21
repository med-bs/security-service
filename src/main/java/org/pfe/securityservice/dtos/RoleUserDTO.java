package org.pfe.securityservice.dtos;

import lombok.Data;

import java.util.List;

@Data
public class RoleUserDTO {
    private String username;
    private List<String> roleNames;
}
