$(document).ready(function() {
    // Kiểm tra nếu đang ở trang profile thì lấy thông tin người dùng từ token
    if (window.location.pathname.includes('/user/profile')) {
        if (!localStorage.token) {
            alert("Sorry, you are not logged in.");
            window.location.href = "/login";
            return;
        }

        $.ajax({
            type: 'GET',
            url: '/users/me',
            dataType: 'json',
            contentType: 'application/json; charset=utf-8',
            beforeSend: function(xhr) {
                xhr.setRequestHeader('Authorization', 'Bearer ' + localStorage.token);
            },
            success: function(data) {
                $('#profile').html(data.fullName);
                if (data.images) {
                    $('#images').attr('src', data.images);
                }
                if ($('#email-display').length) {
                    $('#email-display').html("Email: " + data.email);
                }
                if ($('#token-display').length) {
                    $('#token-display').text(localStorage.token);
                }
            },
            error: function(xhr, status, error) {
                var errorMsg = "Sorry, you are not logged in.";
                if (xhr.responseJSON && xhr.responseJSON.description) {
                    errorMsg = xhr.responseJSON.description;
                }
                alert(errorMsg);
                localStorage.clear();
                window.location.href = "/login";
            }
        });
    }

    // Hàm đăng xuất (Slide 33)
    $('#logout').click(function() {
        localStorage.clear();
        window.location.href = "/login";
    });

    // Hàm Login (Slide 33)
    $('#login').click(function() {
        var email = document.getElementById('email').value;
        var password = document.getElementById('password').value;

        if (!email || !password) {
            alert("Vui lòng nhập email và mật khẩu");
            return;
        }

        var basicInfo = JSON.stringify({
            email: email,
            password: password
        });

        $.ajax({
            type: "POST",
            url: "/auth/login",
            dataType: 'json',
            contentType: "application/json; charset=utf-8",
            data: basicInfo,
            success: function(data) {
                localStorage.token = data.token;
                window.location.href = "/user/profile";
            },
            error: function(xhr) {
                var errorMsg = "Login Failed";
                if (xhr.responseJSON && xhr.responseJSON.description) {
                    errorMsg = xhr.responseJSON.description;
                }
                alert(errorMsg);
            }
        });
    });
});
