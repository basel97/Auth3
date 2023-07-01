



using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using MimeKit;
using MimeKit.Text;
using ModelLayer.DTO;
using ModelLayer.Helper;
using ModelLayer.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace DataLayer.Services
{
    public class AuthenticationServices : IAuth
    {
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly UserManager<CustomIdentityUser> _userManager;
        private IConfiguration _conf;

        public AuthenticationServices(UserManager<CustomIdentityUser> userManager, IConfiguration conf, RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
            _userManager = userManager;
            _conf = conf;
        }
        public async Task<CustomResult> OnRegisterAsync(RegisterDTO regInfo)
        {
            CustomResult result = new CustomResult();
            var ExistUser = await _userManager.FindByEmailAsync(regInfo.Email);
            var emailPattern=EmailValidation.CheckEmailRegex(regInfo.Email);
            if (ExistUser != null||!emailPattern)
            {
                result.Message = "Email ALready Taken or Invalid";
                return result;
            }
            CustomIdentityUser user = new CustomIdentityUser()
            {
                FirstName = regInfo.FirstName,
                LastName = regInfo.LastName,
                UserName = regInfo.UserName,
                Email = regInfo.Email,
            };
            IdentityResult res = await _userManager.CreateAsync(user, regInfo.Password);
            if (!res.Succeeded)
            {
                StringBuilder str = new StringBuilder();
                foreach (var err in res.Errors)
                {
                    str.Append(err.Description + Environment.NewLine);
                }
                return new CustomResult { Message = str.ToString() };
            }
            await _userManager.AddToRoleAsync(user, "User");
            var userRoles = await _userManager.GetRolesAsync(user);
            return new CustomResult
            {
                Message = "Created Successfully",
                IsAuthenticated = true,
                Roles = userRoles.ToList(),
                Email = user.Email,
                UserName = user.UserName
            };

        }
        public async Task<CustomResult> OnLoginAsync(LoginDTO logInfo)
        {
            var result = new CustomResult();
            var user = await _userManager.FindByEmailAsync(logInfo.Email);
            if (user is null || !await _userManager.CheckPasswordAsync(user, logInfo.Password))
            {
                result.Message = "Incorrect Email or Password";
                return result;
            }
            var userToken = await CreateJWTAsync(user);
            var userRoles = await _userManager.GetRolesAsync(user);
            return new CustomResult()
            {
                Message = "login Success",
                Roles = userRoles.ToList(),
                IsAuthenticated = true,
                Token = userToken
            };
        }
        //public async Task<CustomResult> OnLoginWithGoogleAsync(test e)
        //{
        //    var clientId = new GoogleJsonWebSignature.ValidationSettings()
        //    {
        //        Audience = new List<string> { _conf.GetSection("Google:clientId").Value }
        //    };
        //    var payload=await GoogleJsonWebSignature.ValidateAsync(e.code, clientId);
        //    if(payload is not null)
        //    {
        //        CustomIdentityUser user = new CustomIdentityUser()
        //        {
        //            FirstName = payload.GivenName,
        //            Email = payload.Email,
        //            LastName = payload.FamilyName,
        //            UserName = payload.Name
        //        };
        //        await _userManager.CreateAsync(user);
        //       await _userManager.AddToRoleAsync(user, "User");
        //       var token= await CreateJWTAsync(user);
        //        return new CustomResult()
        //        {
        //            Message = "Login Successfully",
        //            Token = token,
        //            IsAuthenticated= true,
        //        };
        //    }
        //    return new CustomResult() { Message = "Failed to login" };
        //}
        public async Task<string> CreateJWTAsync(CustomIdentityUser user)
        {
            var roles = await _userManager.GetRolesAsync(user);
            var userClaims = new List<Claim>()
         {
             new Claim(ClaimTypes.Name,$"{user.FirstName} {user.LastName}"),
         };
            foreach (var role in roles)
            {
                userClaims.Add(new Claim(ClaimTypes.Role, role));
            }
            var identity = new ClaimsIdentity(userClaims);
            var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_conf.GetSection("JWT:Key").Value));

            var credintials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = identity,
                Expires = DateTime.Now.AddDays(double.Parse(_conf.GetSection("JWT:DurationInDays").Value)),
                SigningCredentials = credintials
            };
            var token = new JwtSecurityTokenHandler().CreateToken(tokenDescriptor);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public async Task<string> OnSetRoleAsync(RoleSetModelDTO requestInfo)
        {
            var existUser = await _userManager.FindByEmailAsync(requestInfo.Email);
            if (existUser is null || !await _roleManager.RoleExistsAsync(requestInfo.Role))
            {
                return "Invalid User Or Role!";
            }
            if (await _userManager.IsInRoleAsync(existUser, requestInfo.Role))
                return $"User Already Have The Role {requestInfo.Role} ";
            var res = await _userManager.AddToRoleAsync(existUser, requestInfo.Role);
            return res.Succeeded ? string.Empty : "Request Failed";
        }

        public void SendEmail(EmailDTO emailObj)
        {
            var email = new MimeMessage();
            email.To.Add(MailboxAddress.Parse(emailObj.Email));
            email.From.Add(MailboxAddress.Parse(_conf.GetSection("EmailConfig:email").Value));
            email.Subject = emailObj.Subject;
            email.Body = new TextPart(TextFormat.Html) { Text = emailObj.Body };
            using var smtp = new SmtpClient();
            smtp.Connect(_conf.GetSection("EmailConfig:smtp").Value,
                int.Parse(_conf.GetSection("EmailConfig:port").Value), SecureSocketOptions.StartTls);
            smtp.Authenticate(_conf.GetSection("EmailConfig:email").Value, _conf.GetSection("EmailConfig:pw").Value);
            smtp.Send(email);
            smtp.Disconnect(true);
        }

        public async Task<bool> ForgotPasswordAsync(string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null)
                return false;
            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            //var encodedToken = Encoding.UTF8.GetBytes(token);
            //var validToken = WebEncoders.Base64UrlEncode(encodedToken);
            //var url = $"{_conf.GetSection("Url").Value}/resetpassword?{email}&token={validToken}";
            EmailDTO emailRequest = new EmailDTO()
            {
                Email = user.Email,
                Subject = "Reset Password",
                Body = $"<h4>Use This Token To Reset your password:\n{token}</h4>"
            };
            SendEmail(emailRequest);
            return true;
        }

        public async Task<bool> ResetPasswordAsync(ResetPasswordModelDTO modelInfo)
        {
            var user = await _userManager.FindByEmailAsync(modelInfo.Email);
            if (user == null) return false;
            var res = await _userManager.ResetPasswordAsync(user, modelInfo.Token, modelInfo.Password);
            if (!res.Succeeded)
                return false;
            return true;
        }
    }
}
        