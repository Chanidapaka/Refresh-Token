package sit.int204.jwtdemo.entities.Dto;

import com.fasterxml.jackson.annotation.JsonIgnore;

public class AccessToken {
    @JsonIgnore //ไม่เอาชื่อไปเขียนใน Json
    private final String token;

    //คอนสตัคเตอร์
    public AccessToken(String token) {
        this.token = token;
    }

    public String getAccess_token() {
        return token;
    }
}
