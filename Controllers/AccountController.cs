
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.ComponentModel.DataAnnotations;
using DataLayer.Services;
using ModelLayer.DTO;

namespace AuthModel.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {   
        private readonly IAuth _iAuth;

        public AccountController(IAuth iAuth)
        {
            _iAuth=iAuth;
        }
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody]RegisterDTO registerDTO)
        {
            if(!ModelState.IsValid) 
                return BadRequest(new {message=ModelState});
            var res=await _iAuth.OnRegisterAsync(registerDTO);
            if(res.IsAuthenticated is null)
                return BadRequest(res.Message);
            return Ok(res);
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginDTO loginInfo)
        {
            if(!ModelState.IsValid)
                return BadRequest();
          var res=  await _iAuth.OnLoginAsync(loginInfo);
            if(res.IsAuthenticated is null)
                return NotFound(new {message=res.Message});
            return Ok(new {Message=res.Message,Token=res.Token});



        }
        //[HttpPost("signin-google")]
        //[AllowAnonymous]
        //public async Task<IActionResult> SignInGoogle([FromBody] test t)
        //{
        //    if (credential is null)
        //        return BadRequest();
        //  var result=  await _iAuth.OnLoginWithGoogleAsync(t);
        //    if(result.IsAuthenticated==true)
        //        return Ok(result.Token);
        //    return BadRequest(new {message= "Request Failed !" });

        //}

        [Authorize(Roles ="Admin")]
        [HttpPost("setRole")]
        public async Task<IActionResult> SetRole(RoleSetModelDTO roleRequest)
        {
            if (!ModelState.IsValid)
                return BadRequest();
            var res = await _iAuth.OnSetRoleAsync(roleRequest);
            if (res != string.Empty)
                return NotFound(new { message = res });
            return Ok(new {message="Role Added"});
        }
        [HttpPost("forgotpassword")]
        public async Task<IActionResult> ForgotPassword([FromBody][Required] string email)
        {
            if(email== null)
                return BadRequest();
            var request = await _iAuth.ForgotPasswordAsync(email);
            if (!request)
                return NotFound(new { message = "Invalid Email" });
            return Ok(new {message="Check Your Email to reset password"});
        }
        [HttpPost("resetpassword")]
        public async Task<IActionResult> ResetPassword([FromBody][Required] ResetPasswordModelDTO resetInfo)
        {
            if(!ModelState.IsValid)
                return BadRequest();
            var result=await _iAuth.ResetPasswordAsync(resetInfo);
            if(!result)
                return BadRequest(new { message="Invalid Email or Token"});
            return Ok(new {message="Password Has been reset"});
        }

        [HttpPost("sendemail")]
        public IActionResult SendEmail([FromBody]EmailDTO emailInfo)
        {
            if (!ModelState.IsValid)
                return BadRequest();
            _iAuth.SendEmail(emailInfo);
            return Ok(new { Message = "Sent" });
        }
    }
}
