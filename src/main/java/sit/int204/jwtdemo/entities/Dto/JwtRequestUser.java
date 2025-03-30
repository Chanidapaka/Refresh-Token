package sit.int204.jwtdemo.entities.Dto;

import lombok.Data;

@Data
public class JwtRequestUser {
    private String username;
    private String password;
}