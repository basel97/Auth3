using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using ModelLayer.Models;

namespace DataLayer.Data
{
    public class AppDbContext:IdentityDbContext<CustomIdentityUser>
    {
        public AppDbContext(DbContextOptions opts):base(opts)
        {
            
        }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            
            base.OnModelCreating(builder);
        }
    }
}
