

using ModelLayer.DTO;
using ModelLayer.Models;

namespace DataLayer.Services
{
    public interface IAuth
    {
        public Task<CustomResult> OnRegisterAsync(RegisterDTO regInfo);
        public Task<CustomResult> OnLoginAsync(LoginDTO logInfo);
        public Task<string> CreateJWTAsync(CustomIdentityUser user);
        public Task<string> OnSetRoleAsync(RoleSetModelDTO requestInfo);
        public void SendEmail(EmailDTO emailObj);
        public Task<bool> ForgotPasswordAsync(string email);
        public Task<bool> ResetPasswordAsync(ResetPasswordModelDTO modelInfo);
    }
}
