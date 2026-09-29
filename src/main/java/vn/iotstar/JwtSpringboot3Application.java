package vn.iotstar;

import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;
import vn.iotstar.entity.User;
import vn.iotstar.repository.UserRepository;

@SpringBootApplication
public class JwtSpringboot3Application {

    public static void main(String[] args) {
        SpringApplication.run(JwtSpringboot3Application.class, args);
    }

    /**
     * Tự động khởi tạo tài khoản mẫu trong bài giảng (Slide 28)
     */
    @Bean
    public CommandLineRunner initDatabase(UserRepository userRepository, PasswordEncoder passwordEncoder) {
        return args -> {
            if (userRepository.findByEmail("trungnh@hcmute.edu.vn").isEmpty()) {
                User user = new User();
                user.setFullName("Nguyễn Hữu Trung");
                user.setEmail("trungnh@hcmute.edu.vn");
                user.setPassword(passwordEncoder.encode("123456"));
                user.setImages("https://cdn-icons-png.flaticon.com/512/3135/3135715.png");
                userRepository.save(user);
                System.out.println(">>> Đã khởi tạo tài khoản mẫu: trungnh@hcmute.edu.vn / 123456");
            }
        };
    }
}
