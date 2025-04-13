// === API Endpoint and URL Parameter ===
const apiEndpoint = "https://api.example.com/users?userId=12345";

// === JavaScript URL ===
const jsUrl = "https://cdn.example.com/app.js";

// === Premium Detection Rules / Premium Only ===
// Let's say these are only detected by premium rules in some scanner
const mongoURI = "mongodb+srv://user:password@cluster0.mongodb.net/mydb?retryWrites=true&w=majority";
const passwordInUrl = "https://user:supersecret@secure.example.com";
const awsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const githubToken = "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCDEF";
const googleApiKey = "AIzaSyD1234567890abcdefghijklmn_OPQRST";
const jwtToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.DG7aaJ0bOj5wPb3KOrHkxf3OGOB6Ba-IkfYZhY2IuHU";
const privateKey = `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASC...
-----END PRIVATE KEY-----`;
const sshKey = `ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAsampleSSHkey user@host`;
const basicAuth = "Basic dXNlcm5hbWU6cGFzc3dvcmQ=";
const slackToken = "xoxb-123456789012-0987654321098-AbCdEfGhIjKlMnOpQrStUvWx";
const amazonMwsAuthToken = "amzn.mws.12345678-1234-1234-1234-123456789012";
const facebookAccessToken = "EAAGm0PX4ZCpsBAKZCZCZCZCZCZCZCZCZA6ZD";
const facebookOAuth = "FB-OAuth-Token-Example-1234567890";
const githubAuth = "github:token1234567890example";
const herokuApiKey = "12345678-1234-1234-1234-1234567890ab";
const mailchimpApiKey = "1234567890abcdef-us1";
const mailgunApiKey = "key-3ax6xnjp29jd6fds4gc373sgvjxteol0";
const paypalBraintreeToken = "access_token$sandbox$9xxxxxxxxxxxxxxx4";
const picaticApiKey = "sk_test_4eC39HqLyjWDarjtT1zdp7dc";
const slackWebhook = "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX";
const stripeApiKey = "sk_test_4eC39HqLyjWDarjtT1zdp7dc";
const stripeRestrictedApiKey = "rk_test_TYooMQauvdEDq54NiTphI7jx";
const squareAccessToken = "EAAAEDPugXUvJ0GhZWd_vN0uG7lKqgCq";
const squareOAuthSecret = "sandbox-sq0csp-XXXXXXXXXXXXXXXXXXXX";
const telegramBotApiKey = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11";
const twilioApiKey = "SKXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX";
const githubAuthCreds = {
  username: "user",
  token: "ghp_abcdef1234567890abcdef1234567890abcdef"
};

// === Example Usage for Test ===
console.log("Testing sensitive value detection and endpoint patterns.");
