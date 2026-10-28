const API_URL = "http://127.0.0.1:8000";


/* =========================
   REGISTER
========================= */

const registerForm =
    document.getElementById("registerForm");


if (registerForm) {

    registerForm.addEventListener(
        "submit",
        async function (event) {

            event.preventDefault();


            const name =
                document.getElementById("name").value;

            const email =
                document.getElementById("email").value;

            const password =
                document.getElementById("password").value;


            const message =
                document.getElementById("registerMessage");


            message.innerText = "Creating account...";


            try {

                const response = await fetch(
                    `${API_URL}/auth/register`,
                    {
                        method: "POST",

                        headers: {
                            "Content-Type": "application/json"
                        },

                        body: JSON.stringify({
                            name: name,
                            email: email,
                            password: password
                        })
                    }
                );


                const data = await response.json();


                if (!response.ok) {

                    message.innerText =
                        data.detail || "Registration failed.";

                    return;
                }


                message.innerText =
                    "Account created successfully!";


                setTimeout(() => {

                    window.location.href =
                        "login.html";

                }, 1000);


            } catch (error) {

                console.error(error);

                message.innerText =
                    "Unable to connect to server.";

            }

        }
    );

}


/* =========================
   LOGIN
========================= */

const loginForm =
    document.getElementById("loginForm");


if (loginForm) {

    loginForm.addEventListener(
        "submit",
        async function (event) {

            event.preventDefault();


            const email =
                document.getElementById("loginEmail").value;

            const password =
                document.getElementById("loginPassword").value;


            const message =
                document.getElementById("loginMessage");


            message.innerText =
                "Logging in...";


            try {

                const response = await fetch(
                    `${API_URL}/auth/login`,
                    {
                        method: "POST",

                        headers: {
                            "Content-Type": "application/json"
                        },

                        body: JSON.stringify({
                            email: email,
                            password: password
                        })
                    }
                );


                const data = await response.json();


                if (!response.ok) {

                    message.innerText =
                        data.detail || "Login failed.";

                    return;
                }


                // Store authentication information
                localStorage.setItem(
                    "access_token",
                    data.access_token
                );


                localStorage.setItem(
                    "user",
                    JSON.stringify(data.user)
                );


                message.innerText =
                    "Login successful!";


                setTimeout(() => {

                    window.location.href =
                        "dashboard.html";

                }, 700);


            } catch (error) {

                console.error(error);

                message.innerText =
                    "Unable to connect to server.";

            }

        }
    );

}