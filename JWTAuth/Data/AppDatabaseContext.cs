using JWTAuth.Models;
using Microsoft.EntityFrameworkCore;

namespace JWTAuth.Data
{
    public class AppDatabaseContext: DbContext
    {
        public AppDatabaseContext(DbContextOptions<AppDatabaseContext> options) : base(options)
        {

        }
        public DbSet<User> Users { get; set; }
    }
}
