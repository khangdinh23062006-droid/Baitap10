package vn.iotstar;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import vn.iotstar.entity.User;
import vn.iotstar.models.LoginResponse;
import vn.iotstar.models.LoginUserModel;
import vn.iotstar.models.RegisterUserModel;
import vn.iotstar.repository.UserRepository;
import vn.iotstar.services.JwtService;

import static org.junit.jupiter.api.Assertions.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class JwtSpringboot3ApplicationTests {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private ObjectMapper objectMapper;

    @Test
    @DisplayName("Kiểm tra JwtService với thư viện Nimbus JOSE + JWT")
    void testNimbusJwtService() {
        User testUser = new User();
        testUser.setEmail("testnimbus@example.com");
        testUser.setFullName("Nimbus Tester");

        // 1. Tạo JWT token
        String token = jwtService.generateToken(testUser);
        assertNotNull(token);
        assertTrue(token.split("\\.").length == 3, "JWT token phải có 3 phần header.payload.signature");

        // 2. Trích xuất username
        String username = jwtService.extractUsername(token);
        assertEquals("testnimbus@example.com", username);

        // 3. Kiểm tra tính hợp lệ
        assertTrue(jwtService.isTokenValid(token, testUser));
        assertFalse(jwtService.isTokenExpired(token));
    }

    @Test
    @DisplayName("Test API Đăng ký -> Đăng nhập sinh JWT -> Lấy /users/me")
    void testAuthWorkflow() throws Exception {
        // 1. Đăng ký tài khoản mới qua API /auth/signup
        RegisterUserModel registerUser = new RegisterUserModel();
        registerUser.setEmail("flowuser@hcmute.edu.vn");
        registerUser.setPassword("pass1234");
        registerUser.setFullName("Nguyen Flow User");

        mockMvc.perform(post("/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(registerUser)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("flowuser@hcmute.edu.vn"))
                .andExpect(jsonPath("$.fullName").value("Nguyen Flow User"));

        // 2. Đăng nhập qua API /auth/login
        LoginUserModel loginUser = new LoginUserModel();
        loginUser.setEmail("flowuser@hcmute.edu.vn");
        loginUser.setPassword("pass1234");

        MvcResult loginResult = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginUser)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andExpect(jsonPath("$.expiresIn").value(3600000))
                .andReturn();

        LoginResponse loginResponse = objectMapper.readValue(
                loginResult.getResponse().getContentAsString(),
                LoginResponse.class
        );
        String token = loginResponse.getToken();

        // 3. Truy cập /users/me mà không có Authorization header -> Phải bị chặn
        mockMvc.perform(get("/users/me"))
                .andExpect(status().isForbidden());

        // 4. Truy cập /users/me với Bearer Token -> Thành công 200 OK
        mockMvc.perform(get("/users/me")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("flowuser@hcmute.edu.vn"))
                .andExpect(jsonPath("$.fullName").value("Nguyen Flow User"));

        // 5. Truy cập /users/ để lấy danh sách users -> Thành công 200 OK
        mockMvc.perform(get("/users/")
                        .header("Authorization", "Bearer " + token))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$").isArray());
    }

    @Test
    @DisplayName("Test Tài khoản mẫu trungnh@hcmute.edu.vn từ Slide 28")
    void testSampleUserLogin() throws Exception {
        LoginUserModel loginUser = new LoginUserModel();
        loginUser.setEmail("trungnh@hcmute.edu.vn");
        loginUser.setPassword("123456");

        MvcResult loginResult = mockMvc.perform(post("/auth/login")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(objectMapper.writeValueAsString(loginUser)))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.token").isNotEmpty())
                .andReturn();

        LoginResponse loginResponse = objectMapper.readValue(
                loginResult.getResponse().getContentAsString(),
                LoginResponse.class
        );

        mockMvc.perform(get("/users/me")
                        .header("Authorization", "Bearer " + loginResponse.getToken()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.email").value("trungnh@hcmute.edu.vn"))
                .andExpect(jsonPath("$.fullName").value("Nguyễn Hữu Trung"));
    }
}
